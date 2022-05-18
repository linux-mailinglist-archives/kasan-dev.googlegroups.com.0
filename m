Return-Path: <kasan-dev+bncBDBK55H2UQKRBROGSKKAMGQEX73HFRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 15D6152B3B4
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:41:58 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id bu3-20020a056512168300b0047791fb1d68sf702615lfb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:41:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652859717; cv=pass;
        d=google.com; s=arc-20160816;
        b=xVcJwWw8+z+kGGLucud9+FAu4i5Ns19dvr2adQky6xGCDz1rkH7j1CUeZixrqqSfj+
         m9XugY0rsN5qEeUbX+4yNzlSaHzImSmbd3Gzp/yBix6+WusGAldyJ3VU7g+Q5iORQjku
         Ri2/QPiOZNi0FcF2Qy5W1UTyR7bkI/JAjQBb7JIFQju3CJxR4zDyzZmMJAnRfx8kNCWH
         aQASHscANMGLXZSyhC8NxZfRcHI4vSiQBUYMXNkpQY5UA9artgJDwSsLn85NiZUIJMtw
         OrVFGbLxDhxzr6gwUAlb81mNdINYmGo4BsZk4IpKdn2rHIsjqQHbKkihJewdZ6wSuTGw
         9Hmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=T3RshFdm9Dyj/M6Aj3lBhWjfN3+lb9Ejvig48u/Mv9E=;
        b=TwqIyfjPOVoFwmppVEINfG7eKQu3ydndIKAH5qLGNXy/clTqT5Ha4s5IupGvKNBrUe
         meEbRpUtwt/dyyGH2DJNXo58Hn35/KrgKEfd916ex9WxWuCPLmbsTnZe6fRtybGAa5Il
         tI+VqzFLF5WWUDbdgQ9JxKb3nH17qTR2lcPq0E/9j4lw0/VxYQ6ZKYUdVPvaURJaaD2a
         TyArXFkNKOglOzveh5F+6Zy0ihHhzpqi8LSxh4k8a1LEOpjwOU9jt8ac/comas3X3W1o
         LQB+wM+n+73DHosRAPR/6G7/YgmLPSRVJ6BHi9Ah77b1HkilYnOzQBBAUcOoUSsLwrWz
         ktog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="QI4/JN6C";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T3RshFdm9Dyj/M6Aj3lBhWjfN3+lb9Ejvig48u/Mv9E=;
        b=B/N25c+7qML6yHT7q4bWVAtjQl7GFp6LkKbvIfX1YlHTbpg7PnoNFo9DQJnc8pPA/d
         h9br02+BQqVFKHRzDHMOwHKUDgykKtrzsgOkINEUksoljfPOoFAHI2AlEOBg53wWCPNZ
         anq+IR3TG3Pn1E2HuaAquZL6st+Rd1BFMRYTzwJVtX+upbfPod4o6WfG9I3kbTTz9SrO
         Ui9B/UOkaS9Wsogn3mRgirN+ageqNaMP5ABdQ/WomxrLucWuDGDGs+n6QSbmxGFnvezy
         8QAL039Y49Uixql7jA2kVmr7HcbjNMQ2tSkotw5mv4cEeCePbsT6THgmF/Lph4xHixet
         2w0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=T3RshFdm9Dyj/M6Aj3lBhWjfN3+lb9Ejvig48u/Mv9E=;
        b=d6iAsiCxLn6QOuanIU7gMX9DwOH5pDOTBbDMMmAKXNjt1wnpD4Moc5erq8FeDl8pYW
         Bw752nssLRe3jXubWpPBp63yASffngV7J4gYLiFJfv5ih3TwG9WEd7tL8gQEdrhR2lx/
         FqxBxyVyXyXjAc96XqvvDKufduk6+memCwvNQ8yxgjModhoGHENvwgf1j/kAYyz7Uk/h
         A2FGmiEF3uYIQHUlVUNAzBur9UbvYrypKdwwDhYeggBp0gR6mf2sPqnp3Grvr+wtRFkf
         NMIlV9yKOLpFeN/7m84bOJZJw1ayKVK/zRlK2ilDDilUAoyZWjUW66fwQ51WernRuaUd
         lxpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wRJqc+HjfRYLUNj0v/zYhxuVe4f36m9kvW24P+ZEVrpabf7wl
	M8ceRMOrVOKm4jTf/dUVybo=
X-Google-Smtp-Source: ABdhPJwAHHWFNF8xNCLbQdtw7dyPJ1/u/g5TrH1ZbMHThzgqenSJvmd36lnrQF+8qUb7R2i9q0XYzg==
X-Received: by 2002:ac2:5287:0:b0:472:57c7:d1de with SMTP id q7-20020ac25287000000b0047257c7d1demr19167254lfm.654.1652859717650;
        Wed, 18 May 2022 00:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b888:0:b0:250:638a:caae with SMTP id r8-20020a2eb888000000b00250638acaaels3452138ljp.2.gmail;
 Wed, 18 May 2022 00:41:56 -0700 (PDT)
X-Received: by 2002:a2e:980a:0:b0:24f:37c0:7ad9 with SMTP id a10-20020a2e980a000000b0024f37c07ad9mr16753425ljj.262.1652859716113;
        Wed, 18 May 2022 00:41:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652859716; cv=none;
        d=google.com; s=arc-20160816;
        b=1EK8OBawzSnQGE+vidQsq/s9nkYn5pkak2JMweRpSiC1dhURouM9oL9VqYFLwr7zNN
         ObdvWd3URMAVBRR5r45A9h9pbPeoM2eBY15CtpgQOhHFy/7gjctCclZElqAX+OVBjtty
         A81OGzVwezufV66lc9gex395+60T6POW2FBW5fSnNMeynpyNC12vaG0JXex1gvs3qDwO
         FHdn6il+XGCVVwee89wolLnKyywD+zq9hXtMSjFD0lElDcLxK6PcsdWzcrMAC45bayHb
         3L9QWegZeqaWerjgP77e0Eh0anSyZjSbjIDmeT+QEQaRWmWlbf6F//O5DhJWg87ovRy7
         HSfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=77+MIQsxJm14/HmUlAwrMcbVJVMpzlGQUGBhYiPRONM=;
        b=EYUlX8m+v9kSVg9kO9SIXDDSa1flmM7IQgNO2ReMonUdaVv6M9GnTjOX0k1h48yO9H
         hfaXbQlALQAUp6z7nyjHiziBfQd7LGCCpiZnwS41c8Frqarl1fu1htwpIDUmmSrTDL1e
         eG5TKeJGOIs25C+K2a4t304oJkmiGlAzbPuPfdkfjFDj7hgT18X8jJsOFWgejlVFD7nt
         X9NtjD4VtXAlaE1S6O2bkYnkVmTcd5A1aujNlJEam2EXRfUOFicPeIDeC3AE42xIOIow
         AnQiLZg/GeyR/qnJt+ArhL35FfBuVYjTT5N+e0x3eGTPqLeAs88hYcjDDZD8m/P2uE0S
         0xqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="QI4/JN6C";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bn38-20020a05651c17a600b0024e33a076e7si58673ljb.2.2022.05.18.00.41.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 00:41:56 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrEJe-00BYyb-M7; Wed, 18 May 2022 07:41:54 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 62B4298119B; Wed, 18 May 2022 09:41:52 +0200 (CEST)
Date: Wed, 18 May 2022 09:41:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: [PATCH] objtool: Fix symbol creation
Message-ID: <20220518074152.GB10117@worktop.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518012429.4zqzarvwsraxivux@treble>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="QI4/JN6C";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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
+	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
+	Elf64_Xword entsize = symtab->sh.sh_entsize;
+	Elf32_Word shndx = sym->sec->idx;
+	Elf_Scn *s, *t = NULL;
+	int max_idx, idx = sym->idx;
 
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
+			/* if @idx == 0, it's the next contiguous entry, create it */
+			if (!idx) {
+				void *buf;
+
+				symtab_data = elf_newdata(s);
+				if (t)
+					shndx_data = elf_newdata(t);
+
+				buf = calloc(1, entsize);
+				if (!buf) {
+					WARN("malloc");
+					return -1;
+				}
+
+				symtab_data->d_buf = buf;
+				symtab_data->d_size = entsize;
+				symtab_data->d_align = 1;
+				symtab_data->d_type = ELF_T_SYM;
+
+				symtab->sh.sh_size += entsize;
+				symtab->changed = true;
+
+				if (t) {
+					shndx_data->d_buf = &sym->sec->idx;
+					shndx_data->d_size = sizeof(Elf32_Word);
+					shndx_data->d_align = sizeof(Elf32_Word);
+					shndx_data->d_type = ELF_T_WORD;
+
+					symtab_shndx->sh.sh_size += sizeof(Elf32_Word);
+					symtab_shndx->changed = true;
+				}
 
-	sym->idx = symtab->sh.sh_size / sizeof(sym->sym);
-	elf_dirty_reloc_sym(elf, sym);
+				break;
+			}
 
-	symtab->sh.sh_info += 1;
-	symtab->sh.sh_size += data->d_size;
-	symtab->changed = true;
+			/* we don't do holes in symbol tables */
+			WARN("index out of range");
+			return -1;
+		}
 
-	if (symtab_shndx) {
-		s = elf_getscn(elf->elf, symtab_shndx->idx);
-		if (!s) {
-			WARN_ELF("elf_getscn");
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518074152.GB10117%40worktop.programming.kicks-ass.net.
