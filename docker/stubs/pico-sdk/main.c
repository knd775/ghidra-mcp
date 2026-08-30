/* Near-empty stub. Must not call into the libraries under harvest — that
 * would make --gc-sections on the linked ELF look like a successful corpus
 * when the build-tree objects (which still have the unused functions) are
 * what we actually ingest. */
int main(void) {
    return 0;
}
