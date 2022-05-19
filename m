Return-Path: <kasan-dev+bncBDBK55H2UQKRBNUOTCKAMGQEYHI4HJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4604552CED4
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 11:00:39 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id u11-20020a056000038b00b0020c9ea8b64fsf1310557wrf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 02:00:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652950839; cv=pass;
        d=google.com; s=arc-20160816;
        b=NDZ7xWjz1PDKKTZXpQ6dXf63uNggbIW6LixxRFbFRLtFOOiOmkWgWg7oqB+Qdh1T0o
         xyClyW6QShkPzbOIOswijFI/aZBqfnKMFEomSqB1i+P6NqCvtJF1HmmJY58SUo6Ll3/t
         VtdugyNdBkLfHpbrmSYoSEbCD2SvdE86ni/zDGoHI6sCDQz0WdvqjaiFfjKXBAOXoODk
         zLTuVt9H3rbyF6dvSlesTQ80IJE3AzfSOgxkFpofPZTI4rbBuTpmod51tPBJVHMGYNZQ
         eXNpNIY74Yx9tRV+VLNIB+60BuGOShCKFcFu19V/QuNMkwX5SwF3YC7gkmu/6lcd6e7f
         Yqxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KVty2Wn/EstevvYAvVZV8a658lfEtWtQVlDQt8/dIGM=;
        b=Wip/b2VzoNWkVeMXT4jFCqe8xa0o1IG3Hlho7Vdo4ecrxbFJBxI64Jl4SJo0wyzXce
         xXnUaPLJtEvmvAzMPf4Kdqtp3CZuT+AqXoPkH1rTQ055bmQZOJP40AzsyCIr401MsGmF
         tNGXMvedBBPrrzUK4fooM0+8ozEdzXOTxJkPa612rW6j4sh8DQpIPBaV8EKG8d+WPuZa
         4vxNk8Q4rQg/4rxlp3qIUYkIOm/XUUTlqXA5xUEph58TPBHyxcY7xaMc7cH2nHjQij+a
         k06+j6Dx/i1qIWoPGGKyY0jsRtHZ9pUD6gCvWrCPZk+AKO3/XYkKsfvXYc1kS0I1zXGf
         QGJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ajZp3ndF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KVty2Wn/EstevvYAvVZV8a658lfEtWtQVlDQt8/dIGM=;
        b=ignjpDaW/II/SxWi5xuSW7Jo9I7w51v+vnJySkrLC7YwRiykcBQBRPptZ4UFFlb2CS
         IM/096KSrKPuBwvQHX8rcH6qlgbhQ4FRW3DourA6C29ghzDyg1p85SgThYH09NOI89yD
         gtY2YNkwe7nVCP9q1RfER6Nxm9knYC7tWVmWTl5/Z3dxzP7j+HY+/8erRLAhm7pPKlHf
         Atg3dMsNe+KD6L9b119ffcHkibXS1NgKB6XqCjqKc5Mmmb9hTM95weUatopotmigf5++
         gjihxx198Dg+s50Ybmpq78mg30EJKgeX5xfBJ/EY1VnrClCoPrhbqsWY97mbwYCNQ2Q0
         cliQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KVty2Wn/EstevvYAvVZV8a658lfEtWtQVlDQt8/dIGM=;
        b=M/xtKu6G0r38PftIgJrHNCm5Fb3xv6EFCMzh9oKl2qc8yFdjywO1DYr49ZxhUVWoFz
         dvn8qENUqddTKKfqn5biYLO8k+XD9E2AkyRV4KWatdX5llCG/jcZPOA5zrja3sDnDx5Z
         kvoDC4fNQ/61szN1vsMEMcsq0mvPgGg1HQzrzdofLPkGR8gF81fQj6CiBFXD5evdlGt/
         fGjVu9/WysSmooAx/+BPuS9ccp4QVEUiwne/WaeEJW41zUerDlbb3rQMu0F253Ir/298
         28UCFIiLbUasfX5iqloaDnmXlYiE6Rhk11uGOoKqWsfOdnYkI1T8GhQ7Yo/xPgBnbAbm
         JR9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312UqEsP5+vxWWLRzIPbd4GYaMUuh+43N/r18pxwKEeAdi6WKYg
	K3uRoNScHpmHf/WteQpibio=
X-Google-Smtp-Source: ABdhPJwPC/ImrWaWK6uVyNPb1Wr6vLAU3J6rspdmj/FA7K9/vVATksO45VdHZnbX0HMYthJNL3O8lw==
X-Received: by 2002:a5d:4912:0:b0:20d:5e4:cb1d with SMTP id x18-20020a5d4912000000b0020d05e4cb1dmr3107211wrq.405.1652950838740;
        Thu, 19 May 2022 02:00:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f9d1:0:b0:20e:6336:e09d with SMTP id w17-20020adff9d1000000b0020e6336e09dls3300722wrr.1.gmail;
 Thu, 19 May 2022 02:00:37 -0700 (PDT)
X-Received: by 2002:a5d:4988:0:b0:20d:9b8:e560 with SMTP id r8-20020a5d4988000000b0020d09b8e560mr3038976wrq.33.1652950837464;
        Thu, 19 May 2022 02:00:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652950837; cv=none;
        d=google.com; s=arc-20160816;
        b=06YKE/kzYQFNoj6hOoY+AwSdy4Ef4yaJ5yNIEfeTzM57eCOfArBmPtr3hprJyur8c7
         G2ikih+KJup3BSav+JTYn0vcv32ZbMNXrV1eUpJwYslGNtm+ohuuTOWUTHBtMpOF5jgC
         Q+ipMz5IRHHehoK+chd6j4DEE3JRNhq5XQPxVRqLXC7PqoRpGPGgJZPhTs32PDbOQwhn
         1cM9B7CJ7hc0d1hfkSs5e+mBJnUzhdjy81DNvcbPBMntxqHf9z2zxGr/UOZUZg1n1pEk
         W0fbn30WFXe5120cVv1xgcfnRaNEOQqRp8EyP0GVWS+1MWYUXyZK2sujYoVKqB01sZ8l
         SZBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XrYKEh8RhSLE25PF1iComKvphLhT+lBnN/kFlXkBQ+I=;
        b=oPhg/lwwqlLO05R1jcrSm1IWpCCoquVW2PIup7s+8px/0iHizHbh7Zf9iW+KXz0dax
         M9RYZmMdTRhyVaF/wUd6gyxvfQ7hYa9S2U9E4LUS5/N1iD0KJ+zTjRMPQO0qXFzCdLzW
         RKjiVaYWM0vaKmzoDsnfSakGqgwgFDd/ZIU+P5j7zMfwAfB4AvDu8qdaGC0CtLuUgSfy
         E67vnMACaOvMOZwOvHSo7/J7UcYuityDceQtfqLmhlmHngiN2dlCH6ziZgERxKfbYxol
         pk+6rg8oLKO7HcevUIDxgtB+XNEdZUJjNtclSlrQ8muBk67PL55MufokpvJQf9dp8ih2
         Ik8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ajZp3ndF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id j5-20020a5d4525000000b0020d02df3017si205886wra.6.2022.05.19.02.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 May 2022 02:00:37 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrc1K-001mgJ-5C; Thu, 19 May 2022 09:00:35 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8A7F0980E0B; Thu, 19 May 2022 11:00:29 +0200 (CEST)
Date: Thu, 19 May 2022 11:00:29 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: [PATCH v2] objtool: Fix symbol creation
Message-ID: <20220519090029.GA6479@worktop.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <20220518074152.GB10117@worktop.programming.kicks-ass.net>
 <20220518173604.7gcrjjum6fo2m2ub@treble>
 <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ajZp3ndF;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Subject: objtool: Fix symbol creation
From: Peter Zijlstra <peterz@infradead.org>
Date: Tue, 17 May 2022 17:42:04 +0200

Nathan reported objtool failing with the following messages:

  warning: objtool: no non-local symbols !?
  warning: objtool: gelf_update_symshndx: invalid section index

The problem is due to commit 4abff6d48dbc ("objtool: Fix code relocs
vs weak symbols") failing to consider the case where an object would
have no non-local symbols.

The problem that commit tries to address is adding a STB_LOCAL symbol
to the symbol table in light of the ELF spec's requirement that:

  In each symbol table, all symbols with STB_LOCAL binding preced the
  weak and global symbols.  As ``Sections'' above describes, a symbol
  table section's sh_info section header member holds the symbol table
  index for the first non-local symbol.

The approach taken is to find this first non-local symbol, move that
to the end and then re-use the freed spot to insert a new local symbol
and increment sh_info.

Except it never considered the case of object files without global
symbols and got a whole bunch of details wrong -- so many in fact that
it is a wonder it ever worked :/

Specifically:

 - It failed to re-hash the symbol on the new index, so a subsequent
   find_symbol_by_index() would not find it at the new location and a
   query for the old location would now return a non-deterministic
   choice between the old and new symbol.

 - It failed to appreciate that the GElf wrappers are not a valid disk
   format (it works because GElf is basically Elf64 and we only
   support x86_64 atm.)

 - It failed to fully appreciate how horrible the libelf API really is
   and got the gelf_update_symshndx() call pretty much completely
   wrong; with the direct consequence that if inserting a second
   STB_LOCAL symbol would require moving the same STB_GLOBAL symbol
   again it would completely come unstuck.

Write a new elf_update_symbol() function that wraps all the magic
required to update or create a new symbol at a given index.

Specifically, gelf_update_sym*() require an @ndx argument that is
relative to the @data argument; this means you have to manually
iterate the section data descriptor list and update @ndx.

Fixes: 4abff6d48dbc ("objtool: Fix code relocs vs weak symbols")
Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Tested-by: Nathan Chancellor <nathan@kernel.org>
---
 tools/objtool/elf.c |  198 +++++++++++++++++++++++++++++++++-------------------
 1 file changed, 129 insertions(+), 69 deletions(-)

--- a/tools/objtool/elf.c
+++ b/tools/objtool/elf.c
@@ -374,6 +374,9 @@ static void elf_add_symbol(struct elf *e
 	struct list_head *entry;
 	struct rb_node *pnode;
 
+	INIT_LIST_HEAD(&sym->pv_target);
+	sym->alias = sym;
+
 	sym->type = GELF_ST_TYPE(sym->sym.st_info);
 	sym->bind = GELF_ST_BIND(sym->sym.st_info);
 
@@ -438,8 +441,6 @@ static int read_symbols(struct elf *elf)
 			return -1;
 		}
 		memset(sym, 0, sizeof(*sym));
-		INIT_LIST_HEAD(&sym->pv_target);
-		sym->alias = sym;
 
 		sym->idx = i;
 
@@ -603,24 +604,21 @@ static void elf_dirty_reloc_sym(struct e
 }
 
 /*
- * Move the first global symbol, as per sh_info, into a new, higher symbol
- * index. This fees up the shndx for a new local symbol.
+ * The libelf API is terrible; gelf_update_sym*() takes a data block relative
+ * index value, *NOT* the symbol index. As such, iterate the data blocks and
+ * adjust index until it fits.
+ *
+ * If no data block is found, allow adding a new data block provided the index
+ * is only one past the end.
  */
-static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
-				  struct section *symtab_shndx)
+static int elf_update_symbol(struct elf *elf, struct section *symtab,
+			     struct section *symtab_shndx, struct symbol *sym)
 {
-	Elf_Data *data, *shndx_data = NULL;
-	Elf32_Word first_non_local;
-	struct symbol *sym;
-	Elf_Scn *s;
-
-	first_non_local = symtab->sh.sh_info;
-
-	sym = find_symbol_by_index(elf, first_non_local);
-	if (!sym) {
-		WARN("no non-local symbols !?");
-		return first_non_local;
-	}
+	Elf32_Word shndx = sym->sec ? sym->sec->idx : SHN_UNDEF;
+	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
+	Elf64_Xword entsize = symtab->sh.sh_entsize;
+	int max_idx, idx = sym->idx;
+	Elf_Scn *s, *t = NULL;
 
 	s = elf_getscn(elf->elf, symtab->idx);
 	if (!s) {
@@ -628,79 +626,124 @@ static int elf_move_global_symbol(struct
 		return -1;
 	}
 
-	data = elf_newdata(s);
-	if (!data) {
-		WARN_ELF("elf_newdata");
-		return -1;
+	if (symtab_shndx) {
+		t = elf_getscn(elf->elf, symtab_shndx->idx);
+		if (!t) {
+			WARN_ELF("elf_getscn");
+			return -1;
+		}
 	}
 
-	data->d_buf = &sym->sym;
-	data->d_size = sizeof(sym->sym);
-	data->d_align = 1;
-	data->d_type = ELF_T_SYM;
+	for (;;) {
+		/* get next data descriptor for the relevant sections */
+		symtab_data = elf_getdata(s, symtab_data);
+		if (t)
+			shndx_data = elf_getdata(t, shndx_data);
+
+		/* end-of-list */
+		if (!symtab_data) {
+			void *buf;
+
+			if (idx) {
+				/* we don't do holes in symbol tables */
+				WARN("index out of range");
+				return -1;
+			}
 
-	sym->idx = symtab->sh.sh_size / sizeof(sym->sym);
-	elf_dirty_reloc_sym(elf, sym);
+			/* if @idx == 0, it's the next contiguous entry, create it */
+			symtab_data = elf_newdata(s);
+			if (t)
+				shndx_data = elf_newdata(t);
+
+			buf = calloc(1, entsize);
+			if (!buf) {
+				WARN("malloc");
+				return -1;
+			}
 
-	symtab->sh.sh_info += 1;
-	symtab->sh.sh_size += data->d_size;
-	symtab->changed = true;
+			symtab_data->d_buf = buf;
+			symtab_data->d_size = entsize;
+			symtab_data->d_align = 1;
+			symtab_data->d_type = ELF_T_SYM;
+
+			symtab->sh.sh_size += entsize;
+			symtab->changed = true;
+
+			if (t) {
+				shndx_data->d_buf = &sym->sec->idx;
+				shndx_data->d_size = sizeof(Elf32_Word);
+				shndx_data->d_align = sizeof(Elf32_Word);
+				shndx_data->d_type = ELF_T_WORD;
 
-	if (symtab_shndx) {
-		s = elf_getscn(elf->elf, symtab_shndx->idx);
-		if (!s) {
-			WARN_ELF("elf_getscn");
+				symtab_shndx->sh.sh_size += sizeof(Elf32_Word);
+				symtab_shndx->changed = true;
+			}
+
+			break;
+		}
+
+		/* empty blocks should not happen */
+		if (!symtab_data->d_size) {
+			WARN("zero size data");
 			return -1;
 		}
 
-		shndx_data = elf_newdata(s);
+		/* is this the right block? */
+		max_idx = symtab_data->d_size / entsize;
+		if (idx < max_idx)
+			break;
+
+		/* adjust index and try again */
+		idx -= max_idx;
+	}
+
+	/* something went side-ways */
+	if (idx < 0) {
+		WARN("negative index");
+		return -1;
+	}
+
+	/* setup extended section index magic and write the symbol */
+	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
+		sym->sym.st_shndx = shndx;
+		if (!shndx_data)
+			shndx = 0;
+	} else {
+		sym->sym.st_shndx = SHN_XINDEX;
 		if (!shndx_data) {
-			WARN_ELF("elf_newshndx_data");
+			WARN("no .symtab_shndx");
 			return -1;
 		}
+	}
 
-		shndx_data->d_buf = &sym->sec->idx;
-		shndx_data->d_size = sizeof(Elf32_Word);
-		shndx_data->d_align = 4;
-		shndx_data->d_type = ELF_T_WORD;
-
-		symtab_shndx->sh.sh_size += 4;
-		symtab_shndx->changed = true;
+	if (!gelf_update_symshndx(symtab_data, shndx_data, idx, &sym->sym, shndx)) {
+		WARN_ELF("gelf_update_symshndx");
+		return -1;
 	}
 
-	return first_non_local;
+	return 0;
 }
 
 static struct symbol *
 elf_create_section_symbol(struct elf *elf, struct section *sec)
 {
 	struct section *symtab, *symtab_shndx;
-	Elf_Data *shndx_data = NULL;
-	struct symbol *sym;
-	Elf32_Word shndx;
+	Elf32_Word first_non_local, new_idx;
+	struct symbol *sym, *old;
 
 	symtab = find_section_by_name(elf, ".symtab");
 	if (symtab) {
 		symtab_shndx = find_section_by_name(elf, ".symtab_shndx");
-		if (symtab_shndx)
-			shndx_data = symtab_shndx->data;
 	} else {
 		WARN("no .symtab");
 		return NULL;
 	}
 
-	sym = malloc(sizeof(*sym));
+	sym = calloc(1, sizeof(*sym));
 	if (!sym) {
 		perror("malloc");
 		return NULL;
 	}
-	memset(sym, 0, sizeof(*sym));
-
-	sym->idx = elf_move_global_symbol(elf, symtab, symtab_shndx);
-	if (sym->idx < 0) {
-		WARN("elf_move_global_symbol");
-		return NULL;
-	}
 
 	sym->name = sec->name;
 	sym->sec = sec;
@@ -710,24 +753,41 @@ elf_create_section_symbol(struct elf *el
 	// st_other 0
 	// st_value 0
 	// st_size 0
-	shndx = sec->idx;
-	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
-		sym->sym.st_shndx = shndx;
-		if (!shndx_data)
-			shndx = 0;
-	} else {
-		sym->sym.st_shndx = SHN_XINDEX;
-		if (!shndx_data) {
-			WARN("no .symtab_shndx");
+
+	/*
+	 * Move the first global symbol, as per sh_info, into a new, higher
+	 * symbol index. This fees up a spot for a new local symbol.
+	 */
+	first_non_local = symtab->sh.sh_info;
+	new_idx = symtab->sh.sh_size / symtab->sh.sh_entsize;
+	old = find_symbol_by_index(elf, first_non_local);
+	if (old) {
+		old->idx = new_idx;
+
+		hlist_del(&old->hash);
+		elf_hash_add(symbol, &old->hash, old->idx);
+
+		elf_dirty_reloc_sym(elf, old);
+
+		if (elf_update_symbol(elf, symtab, symtab_shndx, old)) {
+			WARN("elf_update_symbol move");
 			return NULL;
 		}
+
+		new_idx = first_non_local;
 	}
 
-	if (!gelf_update_symshndx(symtab->data, shndx_data, sym->idx, &sym->sym, shndx)) {
-		WARN_ELF("gelf_update_symshndx");
+	sym->idx = new_idx;
+	if (elf_update_symbol(elf, symtab, symtab_shndx, sym)) {
+		WARN("elf_update_symbol");
 		return NULL;
 	}
 
+	/*
+	 * Either way, we added a LOCAL symbol.
+	 */
+	symtab->sh.sh_info += 1;
+
 	elf_add_symbol(elf, sym);
 
 	return sym;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220519090029.GA6479%40worktop.programming.kicks-ass.net.
