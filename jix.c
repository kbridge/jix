#ifdef _MSC_VER
#pragma warning(disable: 4054) // from function pointer '...' to data pointer '...'
#pragma warning(disable: 4127) // conditional expression is constant
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#endif
#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <Windows.h>
#include <fdi.h>
#include "miniz.h"

//////////////////////////////////////////////////////////////////////

// SECTION: Encoding Convert

wchar_t *utf8_to_utf16(const char *s)
{
  int len = 0;
  wchar_t *ws = NULL;
  int n = 0;

  len = (int)strlen(s);
  n = MultiByteToWideChar(CP_UTF8, 0, s, len, NULL, 0);
  ws = (wchar_t *)calloc(n + 1, 2);
  if (ws == NULL) {
    abort();
  }
  MultiByteToWideChar(CP_UTF8, 0, s, len, ws, n);
  ws[n] = 0;

  return ws;
}

char *system_encoding_to_utf8(const char *src)
{
  int len_src;
  int num_wide;
  wchar_t *wbuf;
  int num_utf8;
  char *buf;

  len_src = (int)strlen(src);

  num_wide = MultiByteToWideChar(CP_ACP, 0, src, len_src, NULL, 0);
  wbuf = (wchar_t *)calloc(num_wide + 1, 2);
  if (wbuf == NULL) {
    abort();
  }
  MultiByteToWideChar(CP_ACP, 0, src, len_src, wbuf, num_wide);
  wbuf[num_wide] = 0;
  
  num_utf8 = WideCharToMultiByte(CP_UTF8, 0, wbuf, num_wide, NULL, 0, NULL, 0);
  buf = (char *)malloc(num_utf8 + 1);
  if (buf == NULL) {
    abort();
  }
  WideCharToMultiByte(CP_UTF8, 0, wbuf, num_wide, buf, num_utf8, NULL, 0);
  buf[num_utf8] = 0;

  free(wbuf);
  return buf;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Path Utility

int path_root_length(const char *s)
{
  if (s[0] == '\0') {
    return 0;
  }
  if (s[0] == '\\') {
    return 1;
  }
  if (s[1] == ':') {
    if (s[2] == '\\') {
      return 3;
    }
    return 2;
  }
  return 0;
}

char *path_parent(const char *s)
{
  char *result = NULL;
  int len = 0;
  int root_len = 0;
  int i = 0;

  len = (int)strlen(s);
  root_len = path_root_length(s);

  for (i = len; i > root_len; i--) {
    if (s[i - 1] == '\\' && i != len) {
      i--;
      break;
    }
  }

  result = (char *)malloc(i + 1);
  memcpy(result, s, i);
  result[i] = '\0';
  
  return result;
}

char *path_join(const char *a, const char *b)
{
  int la = 0;
  int lb = 0;
  int sep = 0;
  char *result = NULL;
  char *w = NULL;

  la = (int)strlen(a);
  lb = (int)strlen(b);

  if (la > 0) {
    if (lb == 0) {
      if (a[la - 1] == '\\') {
        la--;
      }
    } else {
      if (a[la - 1] != '\\') {
        sep = 1;
      }
    }
  }

  result = (char *)malloc(la + lb + sep + 1);
  w = result;
  if (la) {
    memcpy(w, a, la);
    w += la;
  }
  if (sep) {
    *w = '\\';
    w++;
  }
  if (lb) {
    memcpy(w, b, lb);
    w += lb;
  }
  *w = '\0';

  return result;
}

//////////////////////////////////////////////////////////////////////

// SECTION: mkdir_recursive

// Path Categories:
//   Empty: "" (NOP)
//   Relative: "a\b"
//   Relative to Current Drive: "\a\b"
//   Absolute: "C:\a\b"
// Special Cases:
//   Path Ending with Backslash
//   Path/Sub Path Exists as Normal File
// Unhandled Cases:
//   Invalid Paths
//   UNC Paths: "\\computer1\a\b"
//   Consecutive Backslashes: "a\\b"
//   Slash: "a/b"
//   Security Issues
//   Race Conditions

int mkdir_recursive(const char *path, unsigned int *error)
{
  int ret = 0;
  int root_len = 0;
  int alen = 0;
  int len = 0;
  unsigned int error_internal = 0;
  wchar_t *str = NULL;
  wchar_t *nonroot = NULL;
  wchar_t *original_end = NULL;
  wchar_t *current_end = NULL;
  wchar_t first_nonroot_char = 0;

  alen = (int)strlen(path);
  len = MultiByteToWideChar(CP_UTF8, 0, path, alen, NULL, 0);
  str = (wchar_t *)calloc(len + 1, 2);
  if (str == NULL) {
    abort();
  }
  MultiByteToWideChar(CP_UTF8, 0, path, alen, str, len);
  str[len] = 0;

  if (len > 0) {
    int last_index = 0;

    if (str[0] == '\\') {
      root_len = 1;
    } else if (len >= 3 && str[1] == ':') {
      root_len = 3;
    }

    last_index = len - 1;

    if (last_index >= root_len && str[last_index] == '\\') {
      str[last_index] = '\0';
      len--;
    }
  }

  nonroot = str + root_len;
  original_end = str + len;
  current_end = original_end;
  first_nonroot_char = nonroot[0];

  for (;;) {
    unsigned int attr = 0;
    
    if (current_end == nonroot) {
      if (current_end != str && GetFileAttributesW(str) == INVALID_FILE_ATTRIBUTES) {
        error_internal = GetLastError();
        goto exit;
      }
      break;
    }

    attr = GetFileAttributesW(str);

    if (attr == INVALID_FILE_ATTRIBUTES) {
      unsigned int err = GetLastError();
      if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
        //printf("[DEBUG] dir '%ls' not exist\n", str);
      } else {
        error_internal = err;
        goto exit;
      }
    } else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
      //printf("[DEBUG] dir '%ls' exist\n", str);
      break;
    } else {
      error_internal = ERROR_ALREADY_EXISTS;
      goto exit;
    }

    while (current_end > nonroot) {
      current_end--;
      if (*current_end == '\\') {
        break;
      }
    }
    *current_end = '\0';
  }

  //printf("[DEBUG] dir base: '%ls'\n", str);

  while (current_end != original_end) {
    if (current_end != original_end) {
      *current_end = (current_end == nonroot) ? first_nonroot_char : '\\';
      do {
        current_end++;
      } while (*current_end != '\0');
    }

    //printf("[DEBUG] create dir: '%ls'\n", str);

    if (!CreateDirectoryW(str, NULL)) {
      error_internal = GetLastError();
      goto exit;
    }
  }

  ret = 1;

exit:
  if (error != NULL) {
    *error = error_internal;
  }
  free(str);
  return ret;
}

//////////////////////////////////////////////////////////////////////

// SECTION: walk_dir

struct file_info
{
  const char *full_path; // 'full' does not imply 'absolute'
  const char *rel_path;
  const char *name;
  int is_dir;
};

#define NEXT_POWER_OF_TWO(ret, v) \
  do {                            \
    int val = v;                  \
    val--;                        \
    val |= val >> 1;              \
    val |= val >> 2;              \
    val |= val >> 4;              \
    val |= val >> 8;              \
    val |= val >> 16;             \
    val++;                        \
    ret = val;                    \
  } while (0)

void walk_dir(const char *base_path, int (*fn)(void *, struct file_info *), void *param)
{
  enum routine_state
  {
    START1,
    START2,
    LOOP_BEGIN_1,
    LOOP_BEGIN_2,
    BEFORE_RECURSE_1,
    BEFORE_RECURSE_2,
    AFTER_RECURSE,
    AFTER_DIR,
    LOOP_END,
    RETURN,
    BUF8_PREPARE_APPEND,
    BUF16_PREPARE_APPEND,
  };

  // because of the re-alloc, directly referencing to frame variables is dangerous

  struct stack_frame
  {
    enum routine_state state;
    int base_len;
    int wbase_len;
    void *hfind;
    WIN32_FIND_DATAW data;
    int success;

    const wchar_t *wfile_name;
    int wfile_name_len;
    int n;
  };

  struct execution_stack
  {
    struct stack_frame default_frames[4];
    struct stack_frame *frames;
    int num_frames;
    int capacity;
  };

  struct path_buf_utf8
  {
    char default_buf[260];
    char *buf;
    int len;
    int cap;
  };

  struct path_buf_utf16
  {
    wchar_t default_buf[260];
    wchar_t *buf;
    int len; // in chars
    int cap; // in bytes
  };

  struct path_buf_utf8 buf8;
  struct path_buf_utf16 buf16;
  int rel_base_len;
  struct execution_stack st;
  struct stack_frame *top;

  int extra = 0;
  enum routine_state return_state = (enum routine_state)0;
  
  struct file_info info;

  {
    int base_path_len = (int)strlen(base_path);
    int need_backslash = (base_path_len > 0 && base_path[base_path_len - 1] != '\\');

    {
      int cap = base_path_len + need_backslash + 1;
      if (cap <= sizeof(buf8.default_buf)) {
        buf8.buf = buf8.default_buf;
        buf8.cap = sizeof buf8.default_buf;
      } else {
        int actual_cap;
        NEXT_POWER_OF_TWO(actual_cap, cap);
        buf8.buf = (char *)malloc(actual_cap);
        if (buf8.buf == NULL) {
          abort();
        }
        buf8.cap = actual_cap;
      }
      buf8.len = 0;
      buf8.buf[0] = '\0';
    }

    memcpy(buf8.buf + buf8.len, base_path, base_path_len);
    buf8.len += base_path_len;

    if (need_backslash) {
      buf8.buf[buf8.len] = '\\';
      buf8.len++;
    }
    buf8.buf[buf8.len] = '\0';
  }
  
  {
    int needed;
    buf16.len = MultiByteToWideChar(CP_UTF8, 0, buf8.buf, buf8.len, NULL, 0);
    needed = (buf16.len + 1) * 2;
    if (needed <= sizeof buf16.default_buf) {
      buf16.cap = sizeof buf16.default_buf;
      buf16.buf = buf16.default_buf;
    } else {
      NEXT_POWER_OF_TWO(buf16.cap, needed);
      buf16.buf = (wchar_t *)malloc(buf16.cap);
      if (buf16.buf == NULL) {
        abort();
      }
    }
    MultiByteToWideChar(CP_UTF8, 0, buf8.buf, buf8.len, buf16.buf, buf16.len);
    buf16.buf[buf16.len] = L'\0';
  }

  rel_base_len = buf8.len;

  st.frames = st.default_frames;
  st.num_frames = 0;
  st.capacity = sizeof st.default_frames;

  top = st.frames;
  top->state = START1;
  st.num_frames++;

dispatch:
  switch (top->state) {
  case START1:
    top->base_len = buf8.len;
    top->wbase_len = buf16.len;

    extra = 1;
    top->state = BUF16_PREPARE_APPEND;
    return_state = START2;
    goto dispatch;
  case START2:
    buf16.buf[buf16.len] = L'*';
    buf16.len++;
    buf16.buf[buf16.len] = L'\0';

    top->hfind = FindFirstFileW(buf16.buf, &top->data);

    buf16.buf[top->wbase_len] = L'\0';
    buf16.len = top->wbase_len;

    top->state = (top->hfind == INVALID_HANDLE_VALUE) ? RETURN : LOOP_BEGIN_1;
    goto dispatch;
  case LOOP_BEGIN_1:
    {
      const wchar_t *ws = top->data.cFileName;
      top->wfile_name = ws;
      if (ws[0] == L'.' && (ws[1] == L'\0' || (ws[1] == L'.' && ws[2] == L'\0'))) {
        top->state = LOOP_END;
        goto dispatch;
      }
    }
    top->wfile_name_len = (int)wcslen(top->wfile_name);
    top->n = WideCharToMultiByte(CP_UTF8, 0, top->wfile_name, top->wfile_name_len, NULL, 0, NULL, NULL);

    extra = top->n;
    top->state = BUF8_PREPARE_APPEND;
    return_state = LOOP_BEGIN_2;
    goto dispatch;
  case LOOP_BEGIN_2:
    {
      int is_dir;

      WideCharToMultiByte(CP_UTF8, 0, top->wfile_name, top->wfile_name_len, buf8.buf + buf8.len, top->n, NULL, NULL);
      buf8.len += top->n;
      buf8.buf[buf8.len] = '\0';

      is_dir = (top->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

      info.full_path = buf8.buf;
      info.rel_path = buf8.buf + rel_base_len;
      info.name = buf8.buf + top->base_len;
      info.is_dir = is_dir;

      top->success = fn(param, &info);

      if (top->success && is_dir) {
        extra = top->n;
        top->state = BUF8_PREPARE_APPEND;
        return_state = BEFORE_RECURSE_1;
      } else {
        top->state = AFTER_DIR;
      }

      goto dispatch;
    }
  case BEFORE_RECURSE_1:
      buf8.buf[buf8.len] = '\\';
      buf8.len++;

      extra = top->wfile_name_len + 1;
      top->state = BUF16_PREPARE_APPEND;
      return_state = BEFORE_RECURSE_2;
      goto dispatch;
  case BEFORE_RECURSE_2:
      memcpy(buf16.buf + buf16.len, top->wfile_name, top->wfile_name_len * 2);
      buf16.len += top->wfile_name_len;
      buf16.buf[buf16.len] = L'\\';
      buf16.len++;
      buf16.buf[buf16.len] = L'\0';

      top->state = AFTER_RECURSE;
      {
        int needed = sizeof(struct stack_frame) * (st.num_frames + 1);
        if (needed > st.capacity) {
          NEXT_POWER_OF_TWO(st.capacity, needed);
          if (st.frames == st.default_frames) {
            st.frames = (struct stack_frame *)malloc(st.capacity);
            if (st.frames == NULL) {
              abort();
            }
            memcpy(st.frames, st.default_frames, st.num_frames * sizeof(struct stack_frame));
          } else {
            st.frames = (struct stack_frame *)realloc(st.frames, st.capacity);
            if (st.frames == NULL) {
              abort();
            }
          }
        }
        top = st.frames + st.num_frames;
        top->state = START1;
        st.num_frames++;
      }
      goto dispatch;
  case AFTER_RECURSE:
    buf16.buf[top->wbase_len] = L'\0';
    buf16.len = top->wbase_len;

    top->state = AFTER_DIR;
    goto dispatch;
  case AFTER_DIR:
    buf8.buf[top->base_len] = '\0';
    buf8.len = top->base_len;

    top->state = top->success ? LOOP_END : RETURN;
    goto dispatch;
  case LOOP_END:
    top->state = FindNextFileW(top->hfind, &top->data) ? LOOP_BEGIN_1 : RETURN;
    goto dispatch;
  case RETURN:
    st.num_frames--;
    if (st.num_frames > 0) {
      top = st.frames + st.num_frames - 1;
      goto dispatch;
    }
    break;
  case BUF8_PREPARE_APPEND:
    {
      int needed = buf8.len + 1 + extra;
      if (needed > buf8.cap) {
        NEXT_POWER_OF_TWO(buf8.cap, needed);
        if (buf8.buf == buf8.default_buf) {
          buf8.buf = (char *)malloc(buf8.cap);
          if (buf8.buf == NULL) {
            abort();
          }
          memcpy(buf8.buf, buf8.default_buf, buf8.len + 1);
        } else {
          buf8.buf = (char *)realloc(buf8.buf, buf8.cap);
          if (buf8.buf == NULL) {
            abort();
          }
        }
      }
      top->state = return_state;
      goto dispatch;
    }
  case BUF16_PREPARE_APPEND:
    {
      int needed = (buf16.len + 1 + extra) * 2;
      
      if (needed > buf16.cap) {
        NEXT_POWER_OF_TWO(buf16.cap, needed);
        if (buf16.buf == buf16.default_buf) {
          buf16.buf = (wchar_t *)malloc(buf16.cap);
          if (buf16.buf == NULL) {
            abort();
          }
          memcpy(buf16.buf, buf16.default_buf, (buf16.len + 1) * 2);
        } else {
          buf16.buf = (wchar_t *)realloc(buf16.buf, buf16.cap);
          if (buf16.buf == NULL) {
            abort();
          }
        }
      }

      top->state = return_state;
      goto dispatch;
    }
  }

  if (st.frames != st.default_frames) {
    free(st.frames);
  }
  if (buf16.buf != buf16.default_buf) {
    free(buf16.buf);
  }
  if (buf8.buf != buf8.default_buf) {
    free(buf8.buf);
  }
}

#undef NEXT_POWER_OF_TWO

//////////////////////////////////////////////////////////////////////

// SECTION: File Mapping

struct file_mapping
{
  void *file_handle;
  void *mapping_handle;
  void *memory;
  unsigned int size;
};

int file_mapping_open(struct file_mapping *fm, const char *path, unsigned int *error)
{
  unsigned int error_internal = 0;
  wchar_t *wpath;
  void *hf;
  void *hm;
  void *mem;
  int ret = 0;

  {
    int len = (int)strlen(path);
    int n = MultiByteToWideChar(CP_UTF8, 0, path, len, NULL, 0);
    wpath = (wchar_t *)calloc(len + 1, 2);
    if (wpath == NULL) {
      abort();
    }
    MultiByteToWideChar(CP_UTF8, 0, path, len, wpath, n);
    wpath[n] = 0;
  }

  hf = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (hf == INVALID_HANDLE_VALUE) {
    error_internal = GetLastError();
    goto exit1;
  }

  hm = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hm == NULL) {
    error_internal = GetLastError();
    goto exit2;
  }

  mem = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
  if (mem == NULL) {
    error_internal = GetLastError();
    goto exit3;
  }

  fm->file_handle = hf;
  fm->mapping_handle = hm;
  fm->memory = mem;
  fm->size = GetFileSize(hf, NULL);

  ret = 1;
  goto exit1;

exit3:
  CloseHandle(hm);
exit2:
  CloseHandle(hf);
exit1:
  free(wpath);

  if (error != NULL) {
    *error = error_internal;
  }
  return ret;
}

int file_mapping_create_temporary(struct file_mapping *fm, int size, unsigned int *error)
{
  unsigned int error_internal = 0;
  wchar_t file_name[13];
  void *hf;
  void *hm;
  void *mem;
  int ret = 0;

  // generate temporary file name
  {
    int i;
    for (i = 0; i < 8; i++) {
      file_name[i] = L"0123456789ABCDEF"[rand() % 16];
    }
    wcscpy(file_name + 8, L".tmp");
  }

  hf = CreateFileW(
    file_name,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
    NULL);
  if (hf == INVALID_HANDLE_VALUE) {
    error_internal = GetLastError();
    goto exit1;
  }

  if (SetFilePointer(hf, size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
    error_internal = GetLastError();
    goto exit2;
  }
  if (!SetEndOfFile(hf)) {
    error_internal = GetLastError();
    goto exit2;
  }
  if (SetFilePointer(hf, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
    error_internal = GetLastError();
    goto exit2;
  }

  hm = CreateFileMappingW(hf, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (hm == INVALID_HANDLE_VALUE) {
    error_internal = GetLastError();
    goto exit2;
  }

  mem = MapViewOfFile(hm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
  if (mem == NULL) {
    error_internal = GetLastError();
    goto exit3;
  }

  fm->file_handle = hf;
  fm->mapping_handle = hm;
  fm->memory = mem;
  fm->size = size;

  ret = 1;
  goto exit1;

exit3:
  CloseHandle(hm);
exit2:
  CloseHandle(hf);
exit1:
  if (error != NULL) {
    *error = error_internal;
  }
  return ret;
}

void file_mapping_close(struct file_mapping *fm)
{
  UnmapViewOfFile(fm->memory);
  CloseHandle(fm->mapping_handle);
  CloseHandle(fm->file_handle);
}

//////////////////////////////////////////////////////////////////////

// SECTION: PE File

struct pe_file
{
  char *file_start;
  char *file_end;
  IMAGE_DATA_DIRECTORY *data_dirs;
  IMAGE_SECTION_HEADER *sections;
  int num_sections;
};

#define has_enough(data_begin, file_end, data_size) \
  ((char *)(file_end) - (char *)(data_begin) >= (int)(data_size))

int pe_file_parse(struct pe_file *pe, void *start, int size)
{
  void *file_start = start;
  void *file_end = (char *)file_start + size;
  IMAGE_DOS_HEADER *dos_header = NULL;
  char *nt_header = NULL;
  IMAGE_FILE_HEADER *file_header = NULL;
  char *optional_header = NULL;
  IMAGE_SECTION_HEADER *sections = NULL;

  dos_header = (IMAGE_DOS_HEADER *)file_start;
  if (!has_enough(dos_header, file_end, sizeof(IMAGE_DOS_HEADER))) {
    return 0;
  }
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return 0;
  }

  nt_header = (char *)dos_header + dos_header->e_lfanew;
  if (!has_enough(nt_header, file_end, sizeof(unsigned int))) {
    return 0;
  }
  if (*(unsigned int *)nt_header != IMAGE_NT_SIGNATURE) {
    return 0;
  }

  file_header = (IMAGE_FILE_HEADER *)((char *)nt_header + sizeof(unsigned int));
  if (!has_enough(file_header, file_end, sizeof(IMAGE_FILE_HEADER))) {
    return 0;
  }

  optional_header = (char *)file_header + sizeof(IMAGE_FILE_HEADER);
  if (!has_enough(optional_header, file_end, file_header->SizeOfOptionalHeader)) {
    return 0;
  }

  sections = (IMAGE_SECTION_HEADER *)((char *)optional_header + file_header->SizeOfOptionalHeader);
  if (!has_enough(sections, file_end, sizeof(IMAGE_SECTION_HEADER) * file_header->NumberOfSections)) {
    return 0;
  }

  pe->file_start = (char *)file_start;
  pe->file_end = (char *)file_end;

  pe->data_dirs = file_header->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) ?
    ((IMAGE_OPTIONAL_HEADER64 *)optional_header)->DataDirectory :
    ((IMAGE_OPTIONAL_HEADER32 *)optional_header)->DataDirectory;

  pe->sections = sections;
  pe->num_sections = file_header->NumberOfSections;

  return 1;
}

IMAGE_SECTION_HEADER *pe_file_section_from_rva(struct pe_file *pe, unsigned int rva)
{
  int i;
  for (i = 0; i < pe->num_sections; i++) {
    IMAGE_SECTION_HEADER *section = &pe->sections[i];
    if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
      return section;
    }
  }
  return NULL;
}

void *pe_file_data_in_section(struct pe_file *pe, IMAGE_SECTION_HEADER *section, unsigned int rva)
{
  return pe->file_start + section->PointerToRawData + rva - section->VirtualAddress;
}

//////////////////////////////////////////////////////////////////////

// SECTION: PE File Resource Key

enum resource_key_component_type
{
  RESOURCE_KEY_COMPONENT_ANY,
  RESOURCE_KEY_COMPONENT_ID,
  RESOURCE_KEY_COMPONENT_STRING,
};

struct resource_key_component
{
  enum resource_key_component_type type;
  union
  {
    unsigned int id;
    wchar_t *string;
  };
};

struct resource_key
{
  struct resource_key_component components[3];
};

void resource_key_component_init_any(struct resource_key_component *comp)
{
  comp->type = RESOURCE_KEY_COMPONENT_ANY;
}

void resource_key_component_init_id(struct resource_key_component *comp, unsigned int id)
{
  comp->type = RESOURCE_KEY_COMPONENT_ID;
  comp->id = id;
}

void resource_key_component_init_string(struct resource_key_component *comp, const char *string)
{
  comp->type = RESOURCE_KEY_COMPONENT_STRING;
  comp->string = utf8_to_utf16(string);
}

void resource_key_component_free(struct resource_key_component *comp)
{
  if (comp->type == RESOURCE_KEY_COMPONENT_STRING) {
    free(comp->string);
  }
}

void resource_key_init(struct resource_key *key, const char *s)
{
  struct resource_type_table_entry
  {
    const char *str;
    int str_len;
    int type;
  };

  static struct resource_type_table_entry resource_type_table[] = 
  {
    { "CURSOR",       6,  1 },
    { "BITMAP",       6,  2 },
    { "ICON",         4,  3 },
    { "MENU",         4,  4 },
    { "DIALOG",       6,  5 },
    { "STRING",       6,  6 },
    { "FONTDIR",      7,  7 },
    { "FONT",         4,  8 },
    { "ACCELERATOR",  11, 9 },
    { "RCDATA",       6,  10 },
    { "MESSAGETABLE", 12, 11 },
    { "GROUP_CURSOR", 12, 12 },
    { "GROUP_ICON",   10, 14 },
    { "VERSION",      7,  16 },
    { "MANIFEST",     8,  24 },
  };

  const char *slash = s;
  const char *p;
  int i;

  if (*slash != '/') {
    abort();
  }

  for (i = 0; i < 3; i++) {
    p = slash + 1;
    slash = strchr(p, '/');
    if (slash == NULL) {
      if (i < 2) {
        abort();
      }
      slash = s + strlen(s);
    }
    if (slash == p) {
      abort();
    }
    if (i > 0 && *p == '*') {
      key->components[i].type = RESOURCE_KEY_COMPONENT_ANY;
    } else if (*p >= '0' && *p <= '9') {
      key->components[i].type = RESOURCE_KEY_COMPONENT_ID;
      key->components[i].id = atoi(p);
    } else if (i == 0 && *p == '[' && slash[-1] == ']') {
      int j;
      int count = sizeof resource_type_table / sizeof resource_type_table[0];
      int rt = -1;
      const char *begin = p + 1;
      const char *end = slash - 1;
      int len = (int)(end - begin);
      for (j = 0; j < count; j++) {
        struct resource_type_table_entry *entry = resource_type_table + j;
        if (entry->str_len == len && strncmp(begin, entry->str, len) == 0) {
          rt = entry->type;
          break;
        }
      }
      if (rt < 0) {
        abort();
      }
      key->components[i].type = RESOURCE_KEY_COMPONENT_ID;
      key->components[i].id = rt;
    } else {
      int len = (int)(slash - p);
      int n = MultiByteToWideChar(CP_UTF8, 0, p, len, NULL, 0);
      wchar_t *ws = (wchar_t *)calloc(n + 1, 2);
      if (ws == NULL) {
        abort();
      }
      MultiByteToWideChar(CP_UTF8, 0, p, len, ws, n);
      ws[n] = 0;

      key->components[i].type = RESOURCE_KEY_COMPONENT_STRING;
      key->components[i].string = ws;
    }
  }
}

void resource_key_free(struct resource_key *key)
{
  int i;
  for (i = 0; i < 3; i++) {
    resource_key_component_free(key->components + i);
  }
}

//////////////////////////////////////////////////////////////////////

// SECTION: PE File Resource Section

struct resource_section
{
  struct pe_file *pe;
  char *start;
  char *end;
};

struct resource_data
{
  void *start;
  int size;
};

int resource_section_from_pe_file(struct resource_section *rs, struct pe_file *pe)
{
  IMAGE_DATA_DIRECTORY *resource_dir;
  IMAGE_SECTION_HEADER *section;
  unsigned int size;
  char *start;
  char *end;

  resource_dir = &pe->data_dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resource_dir->VirtualAddress == 0) {
    return 0;
  }

  section = pe_file_section_from_rva(pe, resource_dir->VirtualAddress);
  if (section == NULL) {
    return 0;
  }

  size = (resource_dir->Size < section->SizeOfRawData) ?
    resource_dir->Size :
    section->SizeOfRawData;

  start = (char *)pe_file_data_in_section(pe, section, resource_dir->VirtualAddress);
  end = (char *)start + size;
  
  if (!has_enough(start, pe->file_end, size)) {
    return 0;
  }

  rs->pe = pe;
  rs->start = start;
  rs->end = end;
  return 1;
}


#define RESOURCE_ENTRY_FIND_VARIABLES_DECLARATION                                                     \
  IMAGE_RESOURCE_DIRECTORY *dir;                                                                      \
  IMAGE_RESOURCE_DIRECTORY_ENTRY *entries;                                                            \
  int num_entries;                                                                                    \
  int i;                                                                                              \
  IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;

#define INIT_RESOURCE_ENTRY_FIND()                                                                      \
  do {                                                                                                  \
    dir = (IMAGE_RESOURCE_DIRECTORY *)dir_start;                                                        \
                                                                                                        \
    if (!has_enough(dir, rs->end, sizeof(IMAGE_RESOURCE_DIRECTORY))) {                                  \
      return NULL;                                                                                      \
    }                                                                                                   \
                                                                                                        \
    entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)((char *)dir_start + sizeof(IMAGE_RESOURCE_DIRECTORY)); \
    num_entries = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;                                   \
                                                                                                        \
    if (!has_enough(entries, rs->end, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * num_entries)) {          \
      return NULL;                                                                                      \
    }                                                                                                   \
  } while (0)

#define EXIT_RESOURCE_ENTRY_FIND()  \
  do {                              \
    return NULL;                    \
  } while (0)

#define FOR_EACH_RESOURCE_ENTRY()   \
  for (i = 0; i < num_entries; i++) \
    if (entry = entries + i, 1)

IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_section_find_first_entry(struct resource_section *rs, void *dir_start)
{
  RESOURCE_ENTRY_FIND_VARIABLES_DECLARATION

  INIT_RESOURCE_ENTRY_FIND();

  FOR_EACH_RESOURCE_ENTRY() {
    return entry;
  }

  EXIT_RESOURCE_ENTRY_FIND();
}

IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_section_find_entry_by_id(struct resource_section *rs, void *dir_start, unsigned int id)
{
  RESOURCE_ENTRY_FIND_VARIABLES_DECLARATION
  
  INIT_RESOURCE_ENTRY_FIND();

  FOR_EACH_RESOURCE_ENTRY() {
    if (!entry->NameIsString && entry->Id == id) {
      return entry;
    }
  }

  EXIT_RESOURCE_ENTRY_FIND();
}

IMAGE_RESOURCE_DIRECTORY_ENTRY *resource_section_find_entry_by_wstring(struct resource_section *rs, void *dir_start, const wchar_t *ws)
{
  RESOURCE_ENTRY_FIND_VARIABLES_DECLARATION
  int ws_len;

  INIT_RESOURCE_ENTRY_FIND();

  ws_len = (int)wcslen(ws);

  FOR_EACH_RESOURCE_ENTRY() {
    IMAGE_RESOURCE_DIR_STRING_U *rstr;

    if (!entry->NameIsString) {
      continue;
    }

    rstr = (IMAGE_RESOURCE_DIR_STRING_U *)(rs->start + entry->NameOffset);
    if (!has_enough(rstr, rs->end, sizeof(unsigned short))) {
      continue;
    }

    if (rstr->Length != ws_len) {
      continue;
    }

    if (!has_enough(rstr->NameString, rs->end, sizeof(wchar_t) * rstr->Length)) {
      continue;
    }

    if (wcsncmp(rstr->NameString, ws, ws_len) == 0) {
      return entry;
    }
  }

  EXIT_RESOURCE_ENTRY_FIND();
}

int resource_section_locate_resource_data(struct resource_section *rs, struct resource_key *key, struct resource_data *rd)
{
  void *p = rs->start;
  int i = 0;
  IMAGE_RESOURCE_DATA_ENTRY *data_entry;
  IMAGE_SECTION_HEADER *section;
  void *data_start;

  for (;;) {
    struct resource_key_component *comp = key->components + i;
    IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    
    switch (comp->type) {
    case RESOURCE_KEY_COMPONENT_ANY:
      entry = resource_section_find_first_entry(rs, p);
      break;
    case RESOURCE_KEY_COMPONENT_ID:
      entry = resource_section_find_entry_by_id(rs, p, comp->id);
      break;
    case RESOURCE_KEY_COMPONENT_STRING:
      entry = resource_section_find_entry_by_wstring(rs, p, comp->string);
      break;
    default:
      abort();
    }

    if (entry == NULL) {
      return 0;
    }

    i++;

    if (i == 3) {
      if (entry->DataIsDirectory) {
        return 0;
      }
      data_entry = (IMAGE_RESOURCE_DATA_ENTRY *)(rs->start + entry->OffsetToData);
      break;
    }

    if (!entry->DataIsDirectory) {
      return 0;
    }

    p = rs->start + entry->OffsetToDirectory;
  }

  section = pe_file_section_from_rva(rs->pe, data_entry->OffsetToData);
  if (section == NULL) {
    return 0;
  }

  data_start = pe_file_data_in_section(rs->pe, section, data_entry->OffsetToData);
  if (!has_enough(data_start, rs->pe->file_end, data_entry->Size)) {
    return 0;
  }

  rd->start = data_start;
  rd->size = data_entry->Size;
  return 1;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - Virtual File

typedef int (*virtual_file_read)(void *f, void *buffer, unsigned int buffer_size);
typedef int (*virtual_file_write)(void *f, void *buffer, unsigned int count);
typedef int (*virtual_file_seek)(void *f, int offset, int origin);
typedef int (*virtual_file_close)(void *f);

struct virtual_file_ops
{
  virtual_file_read read;
  virtual_file_write write;
  virtual_file_seek seek;
  virtual_file_close close;
};

struct virtual_file
{
  struct virtual_file_ops *ops;
};

typedef void *(*create_virtual_file)(void *arg);

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - Memory File

extern struct virtual_file_ops memory_file_ops;

struct memory_file
{
  struct virtual_file_ops *ops;
  void *data;
  unsigned int size;
  unsigned int pos;
};

struct memory_file *memory_file_open(void *data, unsigned int size)
{
  struct memory_file *f = (struct memory_file *)malloc(sizeof(struct memory_file));
  f->ops = &memory_file_ops;
  f->data = data;
  f->size = size;
  f->pos = 0;
  return f;
}

int memory_file_read(struct memory_file *f, void *buffer, unsigned int buffer_size)
{
  unsigned int remain = f->size - f->pos;
  unsigned int n = buffer_size > remain ? remain : buffer_size;
  memcpy(buffer, (char *)f->data + f->pos, n);
  f->pos += n;
  return n;
}

int memory_file_write(struct memory_file *f, const void *buffer, unsigned int count)
{
  unsigned int remain = f->size - f->pos;
  if (count > remain) {
    return -1;
  }
  memcpy((char *)f->data + f->pos, buffer, count);
  f->pos += count;
  return count;
}

int memory_file_seek(struct memory_file *f, int offset, int origin)
{
  int new_pos = 0;
  switch (origin) {
  case SEEK_SET:
    new_pos = offset;
    break;
  case SEEK_CUR:
    new_pos = f->pos + offset;
    break;
  case SEEK_END:
    new_pos = f->size + offset;
    break;
  default:
    abort();
  }
  if (new_pos < 0) {
    return -1;
  }
  if (new_pos > (int)f->size) {
    new_pos = f->size;
  }
  f->pos = new_pos;
  return new_pos;
}

int memory_file_close(struct memory_file *f)
{
  free(f);
  return 0;
}

struct virtual_file_ops memory_file_ops =
{
  (virtual_file_read) memory_file_read,
  (virtual_file_write) memory_file_write,
  (virtual_file_seek) memory_file_seek,
  (virtual_file_close) memory_file_close,
};

struct memory_file_create_arg
{
  void *data;
  unsigned int size;
};

struct memory_file *create_memory_file(struct memory_file_create_arg *arg)
{
  return memory_file_open(arg->data, arg->size);
}

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - Disk File

extern struct virtual_file_ops disk_file_ops;

// Opening a memory_file borrows the pointer, while opening a disk_file _moves_ the handle.
// `Move` means closing a disk_file closes the underlying handle too.
// This is usually the behaviour you want.

struct disk_file
{
  struct virtual_file_ops *ops;
  void *handle;
};

struct disk_file *disk_file_open(void *handle)
{
  struct disk_file *f = (struct disk_file *)malloc(sizeof(struct disk_file));
  f->ops = &disk_file_ops;
  f->handle = handle;
  return f;
}

int disk_file_read(struct disk_file *f, void *buffer, unsigned int buffer_size)
{
  unsigned long n = 0;
  if (!ReadFile(f->handle, buffer, buffer_size, &n, NULL)) {
    n = (unsigned long)-1;
  }
  return n;
}

int disk_file_write(struct disk_file *f, const void *buffer, unsigned int count)
{
  unsigned long n = 0;
  if (!WriteFile(f->handle, buffer, count, &n, NULL)) {
    n = (unsigned long)-1;
  }
  return n;
}

int disk_file_seek(struct disk_file *f, int offset, int origin)
{
  return SetFilePointer(f->handle, offset, NULL, origin);
}

int disk_file_close(struct disk_file *f)
{
  CloseHandle(f->handle);
  free(f);
  return 0;
}

struct virtual_file_ops disk_file_ops =
{
  (virtual_file_read) disk_file_read,
  (virtual_file_write) disk_file_write,
  (virtual_file_seek) disk_file_seek,
  (virtual_file_close) disk_file_close,
};

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - FDI Impl

void *cab_alloc(ULONG cb)
{
  void *p = LocalAlloc(0, cb);
  if (p == NULL) {
    abort();
  }
  return p;
}

void cab_free(void *pv)
{
  LocalFree(pv);
}

INT_PTR cab_open(char *pszFile, int oflag, int pmode)
{
  create_virtual_file factory = NULL;
  void *arg = NULL;
  void *vf = NULL;

  UNREFERENCED_PARAMETER(oflag);
  UNREFERENCED_PARAMETER(pmode);

  if (sscanf(pszFile, "%p%p", &factory, &arg) != 2) {
    abort();
  }

  vf = factory(arg);

  return vf == NULL ? -1 : (INT_PTR)vf;
}

UINT cab_read(INT_PTR hf, void *pv, UINT cb)
{
  struct virtual_file *f = (struct virtual_file *)hf;
  return f->ops->read(f, pv, cb);
}

UINT cab_write(INT_PTR hf, void *pv, UINT cb)
{
  struct virtual_file *f = (struct virtual_file *)hf;
  return f->ops->write(f, pv, cb);
}

int cab_close(INT_PTR hf)
{
  struct virtual_file *f = (struct virtual_file *)hf;
  return f->ops->close(f);
}

long cab_seek(INT_PTR hf, long dist, int seektype)
{
  struct virtual_file *f = (struct virtual_file *)hf;
  return f->ops->seek(f, dist, seektype);
}

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - FDI Utility

const char *fdi_error_string(int error)
{
  static const char *messages[] = {
    "No error",
    "Cabinet not found",
    "Not a cabinet",
    "Unknown cabinet version",
    "Corrupt cabinet",
    "Memory allocation failed",
    "Unknown compression type",
    "Failure decompressing data",
    "Failure writing to target file",
    "Cabinets in set have different RESERVE sizes",
    "Cabinet returned on fdintNEXT_CABINET is incorrect",
    "Application aborted",
  };
  if (error >= 0 && error <= sizeof messages / sizeof *messages) {
    return messages[error];
  }
  return "Unknown error";
}

//////////////////////////////////////////////////////////////////////

// SECTION: Cabinet File - Extraction

struct extract_cab_first_file_to_memory_param
{
  int touched;
  struct file_mapping *fm;
};

INT_PTR extract_cab_first_file_to_memory_notify(FDINOTIFICATIONTYPE type, FDINOTIFICATION *notification)
{
  struct extract_cab_first_file_to_memory_param *param = (struct extract_cab_first_file_to_memory_param *)notification->pv;

  switch (type) {
  case fdintCABINET_INFO:
    return 0;
  case fdintCOPY_FILE:
    {
      unsigned int error;
      unsigned int size = notification->cb;
      struct memory_file *f;
      if (param->touched) {
        return 0; // skip
      }
      param->touched = 1;
      if (!file_mapping_create_temporary(param->fm, size, &error)) {
        fprintf(stderr, "file_mapping_create_temporary() error %u\n", error);
        exit(1);
      }
      f = memory_file_open(param->fm->memory, size);
      return (INT_PTR)f;
    }
  case fdintCLOSE_FILE_INFO:
    {
      struct memory_file *f = (struct memory_file *)notification->hf;
      memory_file_close(f);
      return 1;
    }
  case fdintNEXT_CABINET:
    return -1;
  default:
    return 0;
  }
}

struct extract_cab_first_file_to_disk_param
{
  int touched;
  const char *path;
};

INT_PTR extract_cab_first_file_to_disk_notify(FDINOTIFICATIONTYPE type, FDINOTIFICATION *notification)
{
  struct extract_cab_first_file_to_disk_param *param = (struct extract_cab_first_file_to_disk_param *)notification->pv;

  switch (type) {
  case fdintCABINET_INFO:
    return 0;
  case fdintCOPY_FILE:
    {
      void *hf;

      if (param->touched) {
        return 0; // skip
      }
      param->touched = 1;

      {
        wchar_t *wpath = utf8_to_utf16(param->path);
        hf = CreateFileW(
          wpath,
          GENERIC_WRITE,
          FILE_SHARE_READ,
          NULL,
          CREATE_ALWAYS,
          FILE_ATTRIBUTE_NORMAL,
          NULL);
        free(wpath);
      }
      if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }

      if (SetFilePointer(hf, notification->cb, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "SetFilePointer() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      if (!SetEndOfFile(hf)) {
        fprintf(stderr, "SetEndOfFile() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      if (SetFilePointer(hf, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "SetFilePointer() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }

      return (INT_PTR)disk_file_open(hf);
    }
  case fdintCLOSE_FILE_INFO:
    {
      const int mask = (
        FILE_ATTRIBUTE_READONLY |
        FILE_ATTRIBUTE_HIDDEN |
        FILE_ATTRIBUTE_SYSTEM |
        FILE_ATTRIBUTE_ARCHIVE);
      
      struct disk_file *f = (struct disk_file *)notification->hf;
      void *hf = f->handle;

      {
        unsigned short dos_date = notification->date;
        unsigned short dos_time = notification->time;
        FILETIME ft;
        FILETIME ft_utc;
        if (!(dos_date == 0 && dos_time == 0) &&
            DosDateTimeToFileTime(dos_date, dos_time, &ft) &&
            LocalFileTimeToFileTime(&ft, &ft_utc))
        {
          if (!SetFileTime(hf, NULL, NULL, &ft_utc)) {
            fprintf(stderr, "SetFileTime() error %u\n", (unsigned int)GetLastError());
            exit(1);
          }
        }
      }

      {
        int attrib = attrib = notification->attribs & mask;
        if (attrib != 0) {
          wchar_t *wpath = utf8_to_utf16(param->path);
          if (!SetFileAttributesW(wpath, attrib)) {
            fprintf(stderr, "SetFileAttributes() error %u\n", (unsigned int)GetLastError());
            exit(1);
          }
          free(wpath);
        }
      }

      disk_file_close(f);
      return 1;
    }
  case fdintNEXT_CABINET:
    return -1;
  default:
    return 0;
  }
}

//////////////////////////////////////////////////////////////////////

// SECTION: ZIP Extraction

struct dir_entry
{
  int file_index;
  int num_slashes;
};

int compare_dir_entry(const void *a0, const void *b0)
{
  const struct dir_entry *a = (const struct dir_entry *)a0;
  const struct dir_entry *b = (const struct dir_entry *)b0;
  if (a->num_slashes != b->num_slashes) {
    return b->num_slashes - a->num_slashes;
  }
  return a->file_index - b->file_index;
}

struct dir_vector
{
  struct dir_entry *entries;
  int length;
};

void dir_vector_init(struct dir_vector *v)
{
  v->entries = NULL;
  v->length = 0;
}

void dir_vector_free(struct dir_vector *v)
{
  free(v->entries);
}

void dir_vector_append(struct dir_vector *v, int file_index, int num_slashes)
{
  v->entries = (struct dir_entry *)realloc(v->entries, (v->length + 1) * sizeof(struct dir_entry));
  if (v->entries == NULL) {
    abort();
  }
  v->entries[v->length].file_index = file_index;
  v->entries[v->length].num_slashes = num_slashes;
  v->length++;
}

void adjust_slashes(char *s)
{
  char *p;
  for (p = s; *p != 0; p++) {
    if (*p == '/') {
      *p = '\\';
    }
  }
}

void unix_time_to_file_time(const time_t t, FILETIME *ft)
{
  long long v = (11644473600LL + t) * 10000000;
  ft->dwLowDateTime = (unsigned int)v;
  ft->dwHighDateTime = v >> 32;
}

size_t zip_extract_callback(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
  void *hf = pOpaque;
  unsigned long num_bytes = 0;

  UNREFERENCED_PARAMETER(file_ofs);

  if (!WriteFile(hf, pBuf, (unsigned int)n, &num_bytes, NULL)) {
    return 0;
  }
  return n;
}

void print_mz_zip_error(mz_zip_archive *zip_archive, const char *func)
{
  mz_zip_error error = mz_zip_get_last_error(zip_archive);
  const char *error_string = mz_zip_get_error_string(error);
  fprintf(stderr, "%s() error %d: %s\n", func, error, error_string);
}

void extract_zip(void *buffer, int size, const char *target_dir)
{
  mz_zip_archive zip_archive;
  struct dir_vector dv;
  int num_files = 0;
  int i = 0;

  mz_zip_zero_struct(&zip_archive);

  if (!mz_zip_reader_init_mem(&zip_archive, buffer, size, 0)) {
    print_mz_zip_error(&zip_archive, "mz_zip_reader_init_mem");
    exit(1);
  }

  num_files = (int)mz_zip_reader_get_num_files(&zip_archive);

  dir_vector_init(&dv);

  for (i = 0; i < num_files; i++) {
    mz_zip_archive_file_stat st;

    if (!mz_zip_reader_file_stat(&zip_archive, i, &st)) {
      print_mz_zip_error(&zip_archive, "mz_zip_reader_file_stat");
      exit(1);
    }

    adjust_slashes(st.m_filename);

    if (st.m_is_directory) {
      // we need to create the directory anyway, in case of empty directories
      {
        char *final_path = path_join(target_dir, st.m_filename);
        unsigned int error;
        if (!mkdir_recursive(final_path, &error)) {
          fprintf(stderr, "mkdir_recursive() error %u\n", error);
          exit(1);
        }
        free(final_path);
      }
      {
        int num_slashes = 0;
        const char *p;
        for (p = st.m_filename; *p != 0; p++) {
          if (*p == '\\') {
            num_slashes++;
          }
        }
        dir_vector_append(&dv, i, num_slashes);
      }
    } else {
      char *final_path = path_join(target_dir, st.m_filename);
      wchar_t *final_path_utf16;
      void *hf;

      {
        char *parent_dir = path_parent(final_path);
        unsigned int error;
        if (!mkdir_recursive(parent_dir, &error)) {
          fprintf(stderr, "mkdir_recursive() error %u\n", error);
          exit(1);
        }
        free(parent_dir);
      }

      final_path_utf16 = utf8_to_utf16(final_path);

      hf = CreateFileW(
        final_path_utf16,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
      if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }

      // pre-allocate
      if (SetFilePointer(hf, (long)st.m_uncomp_size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "SetFilePointer() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      if (!SetEndOfFile(hf)) {
        fprintf(stderr, "SetEndOfFile() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      if (SetFilePointer(hf, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "SetFilePointer() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }

      if (!mz_zip_reader_extract_to_callback(&zip_archive, i, zip_extract_callback, hf, 0)) {
        print_mz_zip_error(&zip_archive, "mz_zip_reader_extract_to_callback");
        exit(1);
      }

      if (st.m_time != 0)
      {
        FILETIME ft;
        unix_time_to_file_time(st.m_time, &ft);
        if (!SetFileTime(hf, NULL, NULL, &ft)) {
          fprintf(stderr, "SetFileTime() error %u\n", (unsigned int)GetLastError());
          exit(1);
        }
      }

      CloseHandle(hf);

      {
        const int mask = (
          FILE_ATTRIBUTE_READONLY |
          FILE_ATTRIBUTE_HIDDEN |
          FILE_ATTRIBUTE_SYSTEM |
          FILE_ATTRIBUTE_ARCHIVE);
        int attrib = st.m_external_attr & mask;
        if (attrib != 0 && !SetFileAttributesW(final_path_utf16, attrib)) {
          fprintf(stderr, "SetFileAttributes() error %u\n", (unsigned int)GetLastError());
          exit(1);
        }
      }

      free(final_path_utf16);
      free(final_path);
    }
  }

  qsort(dv.entries, dv.length, sizeof(struct dir_entry), compare_dir_entry);

  for (i = 0; i < dv.length; i++) {
    int file_index = dv.entries[i].file_index;
    mz_zip_archive_file_stat st;
    char *final_path;
    wchar_t *final_path_utf16;

    if (!mz_zip_reader_file_stat(&zip_archive, file_index, &st)) {
      print_mz_zip_error(&zip_archive, "mz_zip_reader_file_stat");
      exit(1);
    }

    adjust_slashes(st.m_filename);

    final_path = path_join(target_dir, st.m_filename);
    final_path_utf16 = utf8_to_utf16(final_path);

    {
      const int file_mask = (
        FILE_ATTRIBUTE_READONLY |
        FILE_ATTRIBUTE_HIDDEN |
        FILE_ATTRIBUTE_SYSTEM |
        FILE_ATTRIBUTE_ARCHIVE); 
      const int dir_mask = (file_mask | FILE_ATTRIBUTE_DIRECTORY);
      if ((st.m_external_attr & file_mask) != 0 &&
          !SetFileAttributesW(final_path_utf16, st.m_external_attr & dir_mask))
      {
        fprintf(stderr, "SetFileAttributes() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
    }

    if (st.m_time != 0)
    {
      void *hf;
      FILETIME ft;

      hf = CreateFileW(
        final_path_utf16,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);
      if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFile() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      unix_time_to_file_time(st.m_time, &ft);
      if (!SetFileTime(hf, NULL, NULL, &ft)) {
        fprintf(stderr, "SetFileTime() error %u\n", (unsigned int)GetLastError());
        exit(1);
      }
      CloseHandle(hf);
    }

    free(final_path_utf16);
    free(final_path);
  }

  dir_vector_free(&dv);

  mz_zip_reader_end(&zip_archive);
}

//////////////////////////////////////////////////////////////////////

// SECTION: Compound File

#if 0
#define DEBUG_PRINTF(...) printf("[DEBUG] " __VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

// A memory wrapper which implements ILockBytes interface
//
// It does not use reference counting mechanism for memory management.
// Allocate it on stack, or allocate it on heap and free it manually.

struct ole_memory
{
  void *vt;
  void *data;
  int size;
};

int __stdcall ole_memory_query_interface(struct ole_memory *m, const IID *riid, void **ppvObject)
{
  if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_ILockBytes)) {
    *ppvObject = m;
    return S_OK;
  }

  *ppvObject = NULL;
  return E_NOINTERFACE;
}

unsigned int __stdcall ole_memory_add_ref(struct ole_memory *m)
{
  UNREFERENCED_PARAMETER(m);
  return 1;
}

unsigned int __stdcall ole_memory_release(struct ole_memory *m)
{
  UNREFERENCED_PARAMETER(m);
  return 1;
}

int __stdcall ole_memory_read_at(struct ole_memory *m, unsigned long long ulOffset, void *pv, unsigned int cb, unsigned int *pcbRead)
{
  unsigned long long remain = (ulOffset >= m->size) ? 0 : (m->size - ulOffset);
  unsigned int n = (cb > remain) ? (unsigned int)remain : cb;
  DEBUG_PRINTF("ole_memory_read_at(offset = %I64u, size = %u)\n", ulOffset, cb);
  memcpy(pv, (char *)m->data + ulOffset, n);
  if (pcbRead != NULL) {
    *pcbRead = n;
  }
  return S_OK;
}

int __stdcall ole_memory_write_at(struct ole_memory *m, unsigned long long ulOffset, void *pv, unsigned int cb, unsigned int *pcbWritten)
{
  unsigned long long remain = (ulOffset >= m->size) ? 0 : (m->size - ulOffset);
  unsigned int n = (cb > remain) ? 0 : cb;
  DEBUG_PRINTF("ole_memory_write_at(offset = %I64u, size = %u)\n", ulOffset, cb);
  memcpy((char *)m->data + ulOffset, pv, n);
  if (pcbWritten) {
    *pcbWritten = n;
  }
  return S_OK;
}

int __stdcall ole_memory_flush(struct ole_memory *m)
{
  UNREFERENCED_PARAMETER(m);
  DEBUG_PRINTF("ole_memory_flush()\n");
  return S_OK;
}

int __stdcall ole_memory_set_size(struct ole_memory *m, unsigned long long cb)
{
  UNREFERENCED_PARAMETER(m);
  UNREFERENCED_PARAMETER(cb);
  DEBUG_PRINTF("ole_memory_set_size(%I64u)\n", cb);
  return E_NOTIMPL;
}

int __stdcall ole_memory_lock_region(struct ole_memory *m, unsigned long long libOffset, unsigned long long cb, unsigned int dwLockType)
{
  UNREFERENCED_PARAMETER(m);
  UNREFERENCED_PARAMETER(libOffset);
  UNREFERENCED_PARAMETER(cb);
  UNREFERENCED_PARAMETER(dwLockType);
  DEBUG_PRINTF("ole_memory_lock_region(offset = %I64u, size = %I64u, type = %u)\n", libOffset, cb, dwLockType);
  return S_OK;
}

int __stdcall ole_memory_unlock_region(struct ole_memory *m, unsigned long long libOffset, unsigned long long cb, unsigned int dwLockType)
{
  UNREFERENCED_PARAMETER(m);
  UNREFERENCED_PARAMETER(libOffset);
  UNREFERENCED_PARAMETER(cb);
  UNREFERENCED_PARAMETER(dwLockType);
  DEBUG_PRINTF("ole_memory_unlock_region(offset = %I64u, size = %I64u, type = %u)\n", libOffset, cb, dwLockType);
  return S_OK;
}

int __stdcall ole_memory_stat(struct ole_memory *m, STATSTG *pstatstg, DWORD grfStatFlag)
{
  UNREFERENCED_PARAMETER(grfStatFlag);
  DEBUG_PRINTF("ole_memory_stat()\n");
  memset(pstatstg, 0, sizeof(STATSTG));
  pstatstg->type = STGTY_LOCKBYTES;
  pstatstg->cbSize.LowPart = m->size;
  return S_OK;
}

void *ole_memory_vtbl[] =
{
  ole_memory_query_interface,
  ole_memory_add_ref,
  ole_memory_release,
  ole_memory_read_at,
  ole_memory_write_at,
  ole_memory_flush,
  ole_memory_set_size,
  ole_memory_lock_region,
  ole_memory_unlock_region,
  ole_memory_stat,
};

void ole_memory_init(struct ole_memory *m, void *data, int size)
{
  m->vt = ole_memory_vtbl;
  m->data = data;
  m->size = size;
}

//////////////////////////////////////////////////////////////////////

// SECTION: MSI Name

#define MSI_CHARS "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
#define MSI_SPECIAL_CHAR '!'
#define MSI_NUM_BITS 6
#define MSI_NUM_CHARS 64
#define MSI_CHAR_MASK 63
#define MSI_START_UNICODE_CHAR 0x3800
#define MSI_END_UNICODE_CHAR 0x4841

int is_msi_name(const wchar_t *ws)
{
  wchar_t ch = ws[0];
  return ch >= MSI_START_UNICODE_CHAR && ch < MSI_END_UNICODE_CHAR;
}

wchar_t *msi_name_to_file_name(const wchar_t *ws, int len)
{
  wchar_t *output;
  wchar_t *w;
  int i;

  output = (wchar_t *)malloc(sizeof(wchar_t) * (len * 2 + 1));
  if (output == NULL) {
    abort();
  }
  w = output;

  for (i = 0; i < len; i++) {
    wchar_t ch = ws[i];
    unsigned int ch0;
    unsigned int ch1;

    if (ch < MSI_START_UNICODE_CHAR || ch >= MSI_END_UNICODE_CHAR) {
      abort();
    }

    ch0 = (ch - MSI_START_UNICODE_CHAR) & MSI_CHAR_MASK;
    ch1 = (ch - MSI_START_UNICODE_CHAR) >> MSI_NUM_BITS;

    if (ch1 <= MSI_NUM_CHARS) {
      *w++ = MSI_CHARS[ch0];
      if (ch1 == MSI_NUM_CHARS) {
        break;
      }
      *w++ = MSI_CHARS[ch1];
    } else {
      *w++ = MSI_SPECIAL_CHAR;
    }
  }

  *w++ = L'\0';
  return output;
}

wchar_t *make_msi_name(const char *s)
{
  const char *msi_chars = MSI_CHARS;
  int len;
  int cap;
  wchar_t *output;
  wchar_t *w;
  int i;
  
  len = (int)strlen(s);
  cap = sizeof(wchar_t) * ((len + 1) / 2 + 1 + 1);
  output = (wchar_t *)malloc(cap);
  if (output == NULL) {
    abort();
  }
  w = output;

  i = 0;
  while (i < len) {
    unsigned int ch0;
    unsigned int ch1;

    if (i == 0 && s[i] == '!') {
      *w++ = 0x4840;
      i++;
      continue;
    }

    {
      const char *p = strchr(msi_chars, s[i]);
      if (p == NULL) {
        abort();
      }
      ch0 = (unsigned int)(p - msi_chars);
    }

    if (s[i + 1] == '\0') {
      ch1 = MSI_NUM_CHARS;
    } else {
      const char *p = strchr(msi_chars, s[i + 1]);
      if (p == NULL) {
        abort();
      }
      ch1 = (unsigned int)(p - msi_chars);
    }

    *w++ = (wchar_t)(MSI_START_UNICODE_CHAR + ((ch1 << MSI_NUM_BITS) | ch0));
    i += 2;
  }

  *w++ = L'\0';
  return output;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Process Creation - Command Line

char *make_command_line(int argc, char **argv)
{
  char *buffer;
  char *w;
  int capacity = 0;
  int i;

  for (i = 0; i < argc; i++) {
    const char *arg = argv[i];
    const char *p;
    int need_quote = 0;
    if (i > 0) {
      capacity++;
    }
    if (arg[0] == '\0') {
      capacity += 2;
      continue;
    }
    for (p = arg; *p != '\0'; p++) {
      capacity++;
      if (*p == '"' || *p == '\\') {
        capacity++;
      } else if (*p == ' ' || *p == '\t') {
        need_quote = 1;
      }
    }
    if (need_quote) {
      capacity += 2;
    }
  }

  buffer = (char *)malloc(capacity + 1);
  if (buffer == NULL) {
    abort();
  }

  w = buffer;
  for (i = 0; i < argc; i++) {
    const char *arg = argv[i];
    const char *p;
    int need_quote = 0;
    int num_backslashes = 0;
    if (i > 0) {
      *w++ = ' ';
    }
    if (arg[0] == '\0') {
      *w++ = '"';
      *w++ = '"';
      continue;
    }
    for (p = arg; *p != '\0'; p++) {
      if (*p == ' ' || *p == '\t') {
        need_quote = 1;
        break;
      }
    }
    if (need_quote) {
      *w++ = '"';
    }
    for (p = arg; *p != '\0'; p++) {
      if (*p == '\\') {
        num_backslashes++;
      } else if (*p == '"') {
        int j;
        for (j = 0; j < num_backslashes; j++) {
          *w++ = '\\';
        }
        num_backslashes = 0;
        *w++ = '\\';
      } else {
        num_backslashes = 0;
      }
      *w++ = *p;
    }
    if (need_quote) {
      int j;
      for (j = 0; j < num_backslashes; j++) {
        *w++ = '\\';
      }
      *w++ = '"';
    }
  }

  *w = '\0';

  return buffer;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Process Creation - Cleanup List

typedef void (*cleanup_func)(void *arg);

struct cleanup_entry
{
  cleanup_func func;
  void *arg;
};

struct cleanup_list
{
  struct cleanup_entry entries[16];
  int count;
};

void cleanup_list_init(struct cleanup_list *cl)
{
  memset(cl, 0, sizeof(struct cleanup_list));
}

void cleanup_list_execute(struct cleanup_list *cl)
{
  int i;
  for (i = cl->count - 1; i >= 0; i--) {
    struct cleanup_entry *entry = &cl->entries[i];
    entry->func(entry->arg);
  }
}

void cleanup_list_append(struct cleanup_list *cl, cleanup_func func, void *arg)
{
  struct cleanup_entry *entry;
  if (cl->count == sizeof(cl->entries) / sizeof(cl->entries[0])) {
    abort();
  }
  entry = &cl->entries[cl->count];
  entry->func = func;
  entry->arg = arg;
  cl->count++;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Process Creation - Redirect

static SECURITY_ATTRIBUTES sa_inheritable = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

int redirect_to_null(void **ptr_handle, struct cleanup_list *cl, unsigned int access, unsigned int *error)
{
  void *handle;

  *error = 0;

  handle = CreateFileW(
    L"NUL",
    access,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    &sa_inheritable,
    OPEN_EXISTING,
    0,
    NULL);
  
  if (handle == INVALID_HANDLE_VALUE) {
    *error = GetLastError();
    return 0;
  }

  *ptr_handle = handle;
  cleanup_list_append(cl, (cleanup_func)CloseHandle, handle);
  return 1;
}

int duplicate_handle(void **ptr_handle, struct cleanup_list *cl, void *handle, unsigned int *error)
{
  void *new_handle;

  *error = 0;

  if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &new_handle, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
    *error = GetLastError();
    return 0;
  }

  *ptr_handle = new_handle;
  cleanup_list_append(cl, (cleanup_func)CloseHandle, new_handle);
  return 1;
}

struct thread_attribute_list
{
  void *buffer;
};

void thread_attribute_list_cleanup(struct thread_attribute_list *tal)
{
  DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)tal->buffer);
  free(tal->buffer);
}

int thread_attribute_list_init(struct thread_attribute_list *tal, struct cleanup_list *cl, int count, unsigned int *error)
{
  void *buffer;
  SIZE_T size;

  *error = 0;

  InitializeProcThreadAttributeList(NULL, count, 0, &size);

  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    *error = GetLastError();
    return 0;
  }

  buffer = malloc(size);
  if (buffer == NULL) {
    abort();
  }

  {
    LPPROC_THREAD_ATTRIBUTE_LIST obj = (LPPROC_THREAD_ATTRIBUTE_LIST)buffer;
    if (!InitializeProcThreadAttributeList(obj, count, 0, &size)) {
      *error = GetLastError();
      free(buffer);
      return 0;
    }
  }

  tal->buffer = buffer;
  cleanup_list_append(cl, (cleanup_func)thread_attribute_list_cleanup, tal);
  return 1;
}

int thread_attribute_list_update_handle_list(struct thread_attribute_list *tal, void **handles, int num_handles, unsigned int *error)
{
  *error = 0;

  {
    LPPROC_THREAD_ATTRIBUTE_LIST obj = (LPPROC_THREAD_ATTRIBUTE_LIST)tal->buffer;
    DWORD_PTR attr = PROC_THREAD_ATTRIBUTE_HANDLE_LIST;
    PVOID value = handles;
    SIZE_T size = num_handles * sizeof(void *);
    if (!UpdateProcThreadAttribute(obj, 0, attr, value, size, NULL, NULL)) {
      *error = GetLastError();
      return 0;
    }
  }
  
  return 1;
}

//////////////////////////////////////////////////////////////////////

// SECTION: Process Creation - Main

int run_program(char *cmdline, unsigned int *exit_code, unsigned int *error)
{
  struct cleanup_list cl;
  int ret = 0;
  wchar_t *cmdline_utf16;
  unsigned int error_internal = 0;
  void *hstdin;
  void *hstdout;
  void *hstderr;
  struct thread_attribute_list tal;
  void *hprocess;
  unsigned int exit_code_internal = 0;

  cleanup_list_init(&cl);

  cmdline_utf16 = utf8_to_utf16(cmdline);
  cleanup_list_append(&cl, free, cmdline_utf16);

  if (!redirect_to_null(&hstdin, &cl, GENERIC_READ, &error_internal)) {
    goto exit;
  }
  if (!redirect_to_null(&hstdout, &cl, GENERIC_WRITE, &error_internal)) {
    goto exit;
  }
  if (!duplicate_handle(&hstderr, &cl, hstdin, &error_internal)) {
    goto exit;
  }

  if (!thread_attribute_list_init(&tal, &cl, 1, &error_internal)) {
    goto exit;
  }

  {
    void *handles[3];
    handles[0] = hstdin;
    handles[1] = hstdout;
    handles[2] = hstderr;

    if (!thread_attribute_list_update_handle_list(&tal, handles, 3, &error_internal)) {
      goto exit;
    }
  }

  {
    STARTUPINFOEXW six;
    STARTUPINFOW *psi = &six.StartupInfo;
    PROCESS_INFORMATION pi;
    int success;

    memset(&six, 0, sizeof six);
    psi->cb = sizeof six;
    psi->dwFlags = STARTF_USESTDHANDLES;
    psi->hStdInput = hstdin;
    psi->hStdOutput = hstdout;
    psi->hStdError = hstderr;
    six.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)tal.buffer;

    success = CreateProcessW(
      NULL,
      cmdline_utf16,
      NULL,
      NULL,
      TRUE,
      EXTENDED_STARTUPINFO_PRESENT,
      NULL,
      NULL,
      psi,
      &pi);
    
    if (!success) {
      error_internal = GetLastError();
      goto exit;
    }

    CloseHandle(pi.hThread);

    hprocess = pi.hProcess;
    cleanup_list_append(&cl, (cleanup_func)CloseHandle, hprocess);
  }

  if (WaitForSingleObject(hprocess, INFINITE) == WAIT_FAILED) {
    error_internal = GetLastError();
    goto exit;
  }

  if (!GetExitCodeProcess(hprocess, (LPDWORD)&exit_code_internal)) {
    error_internal = GetLastError();
    goto exit;
  }

  ret = 1;

exit:
  cleanup_list_execute(&cl);

  if (exit_code != NULL) {
    *exit_code = exit_code_internal;
  }
  if (error != NULL) {
    *error = error_internal;
  }
  return ret;
}

//////////////////////////////////////////////////////////////////////

// SECTION: business logic

struct resource_key rk_tools_zip;
struct resource_key rk_copyright;
struct resource_key rk_src_zip;
struct resource_key rk_data;
struct resource_key rk_installer;

struct string_vector
{
  char **strs;
  int length;
};

void string_vector_init(struct string_vector *v)
{
  v->strs = NULL;
  v->length = 0;
}

void string_vector_free(struct string_vector *v)
{
  if (v->strs != NULL) {
    int i;
    for (i = 0; i < v->length; i++) {
      free(v->strs[i]);
    }
    free(v->strs);
  }
}

void string_vector_append(struct string_vector *v, const char *str)
{
  v->strs = (char **)realloc(v->strs, sizeof(char *) * (v->length + 1));
  if (v->strs == NULL) {
    abort();
  }
  v->strs[v->length] = _strdup(str);
  v->length++;
}

int extract_cab_to_memory(void *input_data, int input_size, struct file_mapping *output_mapping, int *fdi_error)
{
  int ret = 0;
  ERF erf;
  HFDI hfdi;
  struct memory_file_create_arg arg;
  struct extract_cab_first_file_to_memory_param param;
  char buf[36];

  hfdi = FDICreate(
    cab_alloc,
    cab_free,
    cab_open,
    cab_read,
    cab_write,
    cab_close,
    cab_seek,
    cpuUNKNOWN,
    &erf);

  if (hfdi == NULL) {
    *fdi_error = erf.erfOper;
    goto exit1;
  }

  arg.data = input_data;
  arg.size = input_size;

  param.touched = 0;
  param.fm = output_mapping;

  _snprintf(buf, sizeof buf, "%p %p", create_memory_file, &arg);

  if (!FDICopy(hfdi, buf, "", 0, extract_cab_first_file_to_memory_notify, NULL, &param)) {
    *fdi_error = erf.erfOper;
    goto exit2;
  }

  ret = 1;

exit2:
  FDIDestroy(hfdi);

exit1:
  return ret;
}

int extract_cab_to_file(void *input_data, int input_size, const char *path, int *fdi_error)
{
  int ret = 0;
  ERF erf;
  HFDI hfdi;
  struct memory_file_create_arg arg;
  struct extract_cab_first_file_to_disk_param param;
  char buf[36];

  hfdi = FDICreate(
    cab_alloc,
    cab_free,
    cab_open,
    cab_read,
    cab_write,
    cab_close,
    cab_seek,
    cpuUNKNOWN,
    &erf);

  if (hfdi == NULL) {
    *fdi_error = erf.erfOper;
    goto exit1;
  }

  arg.data = input_data;
  arg.size = input_size;

  param.touched = 0;
  param.path = path;

  _snprintf(buf, sizeof buf, "%p %p", create_memory_file, &arg);

  if (!FDICopy(hfdi, buf, "", 0, extract_cab_first_file_to_disk_notify, NULL, &param)) {
    *fdi_error = erf.erfOper;
    goto exit2;
  }

  ret = 1;

exit2:
  FDIDestroy(hfdi);

exit1:
  return ret;
}

int has_suffix(const char *str, const char *suffix, int suffix_len)
{
  int str_len = (int)strlen(str);
  if (str_len < suffix_len) {
    return 0;
  }
  return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

int collect_pack_file(void *param, struct file_info *info)
{
  if (!info->is_dir && has_suffix(info->name, ".pack", sizeof ".pack" - 1)) {
    struct string_vector *sv = (struct string_vector *)param;
    string_vector_append(sv, info->full_path);
  }
  return 1;
}

void final_extract(
  const char *output_dir,
  const char *tools_zip_name,
  void *tools_zip_start,
  int tools_zip_size,
  const char *copyright_name,
  void *copyright_start,
  int copyright_size,
  const char *src_zip_name,
  void *src_zip_start,
  int src_zip_size)
{
  unsigned int error;
  int fdi_error;

  {
    struct file_mapping tools_zip_mapping;

    if (!extract_cab_to_memory(tools_zip_start, tools_zip_size, &tools_zip_mapping, &fdi_error)) {
      fprintf(stderr, "ERROR: extract %s error %d (%s)\n", tools_zip_name, fdi_error, fdi_error_string(fdi_error));
      exit(1);
    }

    extract_zip(tools_zip_mapping.memory, tools_zip_mapping.size, output_dir);

    file_mapping_close(&tools_zip_mapping);
  }

  {
    struct string_vector sv;
    int i;

    string_vector_init(&sv);

    walk_dir(output_dir, collect_pack_file, &sv);

    for (i = 0; i < sv.length; i++) {
      char *args[4];
      char *cmdline;
      unsigned int exit_code;

      args[0] = path_join(output_dir, "bin\\unpack200.exe");
      args[1] = "-r";
      args[2] = sv.strs[i];
      {
        char *s = _strdup(sv.strs[i]);
        strcpy(s + strlen(s) - (sizeof ".pack" - 1), ".jar");
        args[3] = s;
      }
      
      cmdline = make_command_line(4, args);

      free(args[0]);
      free(args[3]);

      if (!run_program(cmdline, &exit_code, &error)) {
        fprintf(stderr, "ERROR: run '%s' error %u\n", cmdline, error);
        exit(1);
      }

      if (exit_code != 0) {
        fprintf(stderr, "ERROR: run '%s' exit code %u\n", cmdline, exit_code);
        exit(1);
      }

      free(cmdline);
    }

    string_vector_free(&sv);
  }

  {
    char *path = path_join(output_dir, "COPYRIGHT");
    if (!extract_cab_to_file(copyright_start, copyright_size, path, &fdi_error)) {
      fprintf(stderr, "ERROR: extract %s error %d (%s)\n", copyright_name, fdi_error, fdi_error_string(fdi_error));
      exit(1);
    }
    free(path);
  }

  {
    char *path = path_join(output_dir, "lib\\src.zip");
    if (!extract_cab_to_file(src_zip_start, src_zip_size, path, &fdi_error)) {
      fprintf(stderr, "ERROR: extract %s error %d (%s)\n", src_zip_name, fdi_error, fdi_error_string(fdi_error));
      exit(1);
    }
    free(path);
  }
}

void extract_jdk7_style_installer(const char *output_dir, struct resource_section *rs)
{
  struct resource_data rd_tools_zip;
  struct resource_data rd_copyright;
  struct resource_data rd_src_zip;

  if (!resource_section_locate_resource_data(rs, &rk_tools_zip, &rd_tools_zip)) {
    fprintf(stderr, "ERROR: resource JAVA_CAB10 (tools.zip) not found\n");
    exit(1);
  }

  if (!resource_section_locate_resource_data(rs, &rk_copyright, &rd_copyright)) {
    fprintf(stderr, "ERROR: resource JAVA_CAB11 (COPYRIGHT) not found\n");
    exit(1);
  }

  if (!resource_section_locate_resource_data(rs, &rk_src_zip, &rd_src_zip)) {
    fprintf(stderr, "ERROR: resource JAVA_CAB9 (src.zip) not found\n");
    exit(1);
  }

  final_extract(
    output_dir,
    "JAVA_CAB10", rd_tools_zip.start, rd_tools_zip.size,
    "JAVA_CAB11", rd_copyright.start, rd_copyright.size,
    "JAVA_CAB9", rd_src_zip.start, rd_src_zip.size);
}

void read_file_in_storage(IStorage *stg, const char *file_name, struct file_mapping *fm)
{
  int hr;
  unsigned int error;
  wchar_t *msi_name;
  IStream *stream;
  STATSTG stat;

  msi_name = make_msi_name(file_name);

  hr = stg->lpVtbl->OpenStream(stg, msi_name, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &stream);
  if (FAILED(hr)) {
    if (hr == STG_E_FILENOTFOUND) {
      fprintf(stderr, "ERROR: level 2 installer does not contain file '%s'", "ss.cab");
    } else {
      fprintf(stderr, "ERROR: IStorage::OpenStream() error 0x%08X\n", hr);
    }
    exit(1);
  }

  hr = stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME);
  if (FAILED(hr)) {
    fprintf(stderr, "ERROR: IStream::Stat() error 0x%08X\n", hr);
    exit(1);
  }

  if (!file_mapping_create_temporary(fm, stat.cbSize.LowPart, &error)) {
    fprintf(stderr, "file_mapping_create_temporary() error %u\n", error);
    exit(1);
  }

  hr = stream->lpVtbl->Read(stream, fm->memory, fm->size, NULL);
  if (FAILED(hr)) {
    fprintf(stderr, "ERROR: IStream::Read() error 0x%08X\n", hr);
    exit(1);
  }

  stream->lpVtbl->Release(stream);

  free(msi_name);
}

void extract_jdk11_style_installer(const char *output_dir, void *data, int size)
{
  int hr;
  struct ole_memory om;
  IStorage *stg;
  struct file_mapping tools_zip_mapping;
  struct file_mapping copyright_mapping;
  struct file_mapping src_zip_mapping;

  ole_memory_init(&om, data, size);

  if (StgIsStorageILockBytes((ILockBytes *)&om) == S_FALSE) {
    fprintf(stderr, "ERROR: level 2 installer is not a valid compound file\n");
    exit(1);
  }

  hr = StgOpenStorageOnILockBytes((ILockBytes *)&om, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &stg);
  if (FAILED(hr)) {
    fprintf(stderr, "ERROR: StgOpenStorageOnILockBytes() error 0x%08X\n", hr);
    exit(1);
  }

  read_file_in_storage(stg, "st.cab", &tools_zip_mapping);
  read_file_in_storage(stg, "sz.cab", &copyright_mapping);
  read_file_in_storage(stg, "ss.cab", &src_zip_mapping);

  final_extract(
    output_dir,
    "st.cab", tools_zip_mapping.memory, tools_zip_mapping.size,
    "sz.cab", copyright_mapping.memory, copyright_mapping.size,
    "ss.cab", src_zip_mapping.memory, src_zip_mapping.size);

  file_mapping_close(&tools_zip_mapping);
  file_mapping_close(&copyright_mapping);
  file_mapping_close(&src_zip_mapping);

  stg->lpVtbl->Release(stg);
}

int main(int argc, char *argv[])
{
  unsigned int error;
  int hr;
  char *installer_path;
  char *output_dir;
  struct file_mapping installer_mapping;
  struct pe_file pe_level0;
  struct resource_section rs_level0;
  struct resource_data rd_level0;
  int unhandled = 0;

  if (argc != 3) {
    printf("usage: jix <installer path> <output directory>\n");
    exit(0);
  }

  srand((unsigned int)time(NULL));

  hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
  if (FAILED(hr)) {
    fprintf(stderr, "ERROR: CoInitialize() error 0x%08X\n", hr);
    exit(1);
  }

  resource_key_init(&rk_tools_zip, "/JAVA_CAB10/*/1033");
  resource_key_init(&rk_copyright, "/JAVA_CAB11/*/1033");
  resource_key_init(&rk_src_zip, "/JAVA_CAB9/*/1033");
  resource_key_init(&rk_data, "/[RCDATA]/100/1033");
  resource_key_init(&rk_installer, "/JAVA_INSTALLER/1/1033");

  installer_path = system_encoding_to_utf8(argv[1]);
  output_dir = system_encoding_to_utf8(argv[2]);

  if (!file_mapping_open(&installer_mapping, installer_path, &error)) {
    fprintf(stderr, "ERROR: cannot open file '%s', error %u\n", installer_path, error);
    exit(1);
  }

  if (!pe_file_parse(&pe_level0, installer_mapping.memory, installer_mapping.size)) {
    fprintf(stderr, "ERROR: installer is not a valid PE file\n");
    exit(1);
  }

  if (!resource_section_from_pe_file(&rs_level0, &pe_level0)) {
    fprintf(stderr, "ERROR: installer does not have a valid resource section\n");
    exit(1);
  }

  if (resource_section_locate_resource_data(&rs_level0, &rk_tools_zip, &rd_level0)) {
    // JDK 7
    extract_jdk7_style_installer(output_dir, &rs_level0);
  } else if (resource_section_locate_resource_data(&rs_level0, &rk_data, &rd_level0)) {
    struct pe_file pe_level1;
    struct resource_section rs_level1;
    struct resource_data rd_level1;

    if (!pe_file_parse(&pe_level1, rd_level0.start, rd_level0.size)) {
      fprintf(stderr, "ERROR: level 1 installer is not a valid PE file\n");
      exit(1);
    }

    if (!resource_section_from_pe_file(&rs_level1, &pe_level1)) {
      fprintf(stderr, "ERROR: level 1 installer does not have a valid resource section\n");
      exit(1);
    }

    if (resource_section_locate_resource_data(&rs_level1, &rk_tools_zip, &rd_level1)) {
      // JDK 8-10
      extract_jdk7_style_installer(output_dir, &rs_level1);
    } else if (resource_section_locate_resource_data(&rs_level1, &rk_installer, &rd_level1)) {
      // JDK 11-14
      extract_jdk11_style_installer(output_dir, rd_level1.start, rd_level1.size);
    } else {
      unhandled = 1;
    }
  } else {
    unhandled = 1;
  }

  if (unhandled) {
    fprintf(stderr, "ERROR: file unrecognized\n");
    exit(1);
  }

  file_mapping_close(&installer_mapping);

  free(installer_path);
  free(output_dir);

  resource_key_free(&rk_tools_zip);
  resource_key_free(&rk_copyright);
  resource_key_free(&rk_src_zip);
  resource_key_free(&rk_data);
  resource_key_free(&rk_installer);

  CoUninitialize();
  return 0;
}
