# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

# --- DIRECTORIES ---
SRCDIR = src
BUILDDIR = build
BINDIR = bin

# --- TARGET ---
TARGET = crypto
EXECUTABLE = $(BINDIR)/$(TARGET)

# --- SOURCES & OBJECTS ---
# List all your .c files here without the path
SOURCES = main.c tea.c chacha20.c rsa.c bignum.c

# Prepend directory paths to sources and objects
SOURCES_WITH_PATH = $(addprefix $(SRCDIR)/, $(SOURCES))
OBJECTS = $(addprefix $(BUILDDIR)/, $(SOURCES:.c=.o))

.PHONY: all clean

# Default rule: build the executable
all: $(EXECUTABLE)

# Rule to create the final executable in the 'bin' directory
$(EXECUTABLE): $(OBJECTS)
	@mkdir -p $(BINDIR) # Create bin directory if it doesn't exist
	$(CC) $(CFLAGS) -o $@ $^

# Rule to compile a .c file from 'src' into a .o file in 'build'
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(BUILDDIR) # Create build directory if it doesn't exist
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up all generated files
clean:
	@echo "Cleaning up build files..."
	rm -rf $(BUILDDIR) $(BINDIR)