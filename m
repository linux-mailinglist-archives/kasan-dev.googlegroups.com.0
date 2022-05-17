Return-Path: <kasan-dev+bncBDBK55H2UQKRBUUER6KAMGQESX6YBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A895F52A71A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 17:42:10 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id u11-20020a056000038b00b0020c9ea8b64fsf4796628wrf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 08:42:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652802130; cv=pass;
        d=google.com; s=arc-20160816;
        b=AMV+06dSGpiAGGnBGYEjTmDJqJQnQHPt6iJUjh8ICfhfRXO7Aqwt50vYFwqcqyLZRZ
         gevY5q12QXIMWufa9QptsDLt9Xn6xOoSxE2SyiQvpFpX3Uv/0Ic6f9wraSoKjUUvdZhn
         qqR3MPw8ARywIH7KGtueSqqCIlI88PqEvf+l8zVbhsb/Ub5W4ePl3TdKUyNz913fpW7X
         6kI4XYi975rKTKmh8jjMaiLbdRrl3wSf1nWLGHlKdATj3N9JAQ1Rg1b5MjvR2iLuoRw4
         JJhQwj4tCV2m+8q4TcjbC6je+BNUyVqCE5ckV9vSNESyiOML0FNOZZvhw7XsEtBMNnCu
         5lwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=elCU6Wz/IVtdMD3kk7+NPYj7FzFAXmn2WStEFywFymI=;
        b=wl/KqaHALMhSVj+IDbUf61RvwlhfXyvFC6qCzInEeNeNiPFziCgkaT7qHbnuscquXU
         QwD8LMl/MhE3B8qQ7nhPb3khQNaLILhBTLRoNG6k+llCJwgSU9x3WHZdzIJ9r94+lImH
         j5hzqwdLRhAXP8xDIfVwLUjI5MtUvAnlsu06WGUTz01M/Teavs2SrOR0l199fsYSRT7d
         xGzZWrWoEVMMX1ZY3G+Z0pbwXeQ8dD9ywnlDl2NnCiSe/MxgMH7lrsFXn/67SQ1Yp/mL
         JHMmMTAmGYSxCTIRvSi+oDOWRD1PKlPk5gCnBJgbD6hTMFHptAw6W9zSmvf03lRXuSIa
         P8Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UWuNvE0x;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=elCU6Wz/IVtdMD3kk7+NPYj7FzFAXmn2WStEFywFymI=;
        b=GFYoPUFnAfufm6HgdoDffp7n55G9M0KcDzSOm3i5lHSQ7GVKMQ+k6hoI9/+fGSUVPa
         hRaQLFqg3cDngCgyDDU0ivqwafjaAYjjkWcT2doMec3hZ+QoDqBL8FJtztmxIaxdlfvB
         xChgyyM0XTTk8Afbkl1R1kMvA1VMaNY3ihYN5VaoLkTHquHMadWqAgKThPE9z8px6C79
         5WFoT9/3C1d9ux1GSoINdckdj6FjYzXQ9tpJBFqBmLov6q6Adhaqp7OFn2cinUcxo4cr
         B+IlKV9+lOGXklAg/yuXJy+IbRAIZXYUC2U5jcDmeFlqUBrMGPTCt5vQegEunHwLlYqB
         Xn8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=elCU6Wz/IVtdMD3kk7+NPYj7FzFAXmn2WStEFywFymI=;
        b=TlENz6tq3Awi4oeKK3dis5A0LGI56PSRKZrrWLc5Pyi5ZdliNwuNzmYzdO9zkeVMIp
         fzL22+kg66DgJ1uD5qd5ktCFG5QH49KWlqQG63mJaD2BOcVa/D8pf6eP2f/jACnyuzZO
         bgMxoD1s2o+bqeKOYIcolrUlHOvia6D8VC0nFrkpbTSeCzxTZvaqcg6DklSV+7nVJOwo
         nJWVkUPxN1MBeepWsUrcLrvokWNev3zUM7rpt1LtA8DuG/jL9ZH9oCsDYRkVfVg1WemR
         JH4JTg+42XwCgK2jk16ncE21fRq803ciit3tOOf+jXOH+bJiijZMr11hcbwdT3hMROGN
         5DTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nG+yqIub8XKO4JzZoYwDljygbVUknQ/rwC17s97U+JYw9bAsw
	anEStLPXCoo5dxLuk1DDlKI=
X-Google-Smtp-Source: ABdhPJwNYovgw6JUupU+pz1cHQn9tT3OP+Ui25fuNfNzOCs+/kQgha7gOOcuQIk/wU2BxZwZ8BEBNg==
X-Received: by 2002:a05:6000:1d90:b0:20c:9efd:bd6b with SMTP id bk16-20020a0560001d9000b0020c9efdbd6bmr19739858wrb.605.1652802130328;
        Tue, 17 May 2022 08:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els3500844wrz.1.gmail; Tue, 17 May 2022
 08:42:09 -0700 (PDT)
X-Received: by 2002:a5d:5847:0:b0:20c:525b:49d0 with SMTP id i7-20020a5d5847000000b0020c525b49d0mr19397214wrf.13.1652802129137;
        Tue, 17 May 2022 08:42:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652802129; cv=none;
        d=google.com; s=arc-20160816;
        b=y2hxortBKO0zZVk5d1EWzMULw8RXptL7YsxuxLctApHvWy8wO7eiHGsMnf4/wrUZ2G
         LS9gR1M3DY+nMgmczWJm8Jx0+aNMY52PJ9TA9u2KBAvXcZQSO36S7eehlHaqwGm98IN8
         rlshlhzuyiaoS2sNOMotGvvyG7vAelNt5By58IfqumjNw47BRn6xvbY8eqwR64ScknHT
         WiX02pwz2ea1d5IGgQkT9c3p+K28wBANKDueXWQRQRN7peSCQoocDbvvpGXDO4wooz0Q
         DdyXICyHuVaUwvFHdwHNxQJ0ZWCD5aU0ui/5ndS2M1Kl4Df8Sww9Sj0l4s1aq1Z0bvhI
         kPsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=C8bFBcYQ8gfp+jZZiMampXlgPGTpsfmScw6kMFrgs3U=;
        b=BkL3ovh+FTi4NcVbfkroIrkHHxnKVVny1gfv1+Dw0iAyLy8lvsJhBIGVdmqC5plyRV
         jGjbNY15EE++NdB/qee6xUNh9JXrFqvdJjtL+cW8tKKjlgTH3Aotqnu804w+/5d1qDJs
         /6BRcpSVxj7r9aVFfE/sxZJ7BjtDtCMEbI9mxpatUJNlnXe1jq8aaDu83OmShFXdb9CA
         LZL5GC/Z5byA827Re9Hz23lsH2UqK81GbTU5WKzihHKyNqX85lgGkWYHChhhp1odAhSp
         sPKUYy0jm9xgfjNOCfB2wLavannZZeyMnsHVHHnaS7s87k4bmbdTDGgkKqxMmf56n32B
         xQdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UWuNvE0x;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id f18-20020adfe912000000b0020d0fc09c53si197763wrm.1.2022.05.17.08.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 May 2022 08:42:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nqzKo-001H0b-MG; Tue, 17 May 2022 15:42:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7B57D3003AA;
	Tue, 17 May 2022 17:42:04 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6036A2040ACD7; Tue, 17 May 2022 17:42:04 +0200 (CEST)
Date: Tue, 17 May 2022 17:42:04 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=UWuNvE0x;
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

On Tue, May 17, 2022 at 05:33:59PM +0200, Peter Zijlstra wrote:
> On Mon, May 16, 2022 at 11:40:06PM +0200, Peter Zijlstra wrote:
> > Does something simple like this work? If not, I'll try and reproduce
> > tomorrow, it shouldn't be too hard to fix.
> 
> Oh, man, I so shouldn't have said that :/
> 
> I have something that almost works, except it now mightly upsets
> modpost.
> 
> I'm not entirely sure how the old code worked as well as it did. Oh
> well, I'll get it sorted.

Pff, it's been a *long* day.. here this works.

---
 tools/objtool/elf.c | 191 ++++++++++++++++++++++++++++++++++------------------
 1 file changed, 125 insertions(+), 66 deletions(-)

diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
index ebf2ba5755c1..a9c3e27527de 100644
--- a/tools/objtool/elf.c
+++ b/tools/objtool/elf.c
@@ -600,24 +600,24 @@ static void elf_dirty_reloc_sym(struct elf *elf, struct symbol *sym)
 }
 
 /*
- * Move the first global symbol, as per sh_info, into a new, higher symbol
- * index. This fees up the shndx for a new local symbol.
+ * The libelf API is terrible; gelf_update_sym*() takes a data block relative
+ * index value. As such, iterate the data blocks and adjust index until it fits.
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
+	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
+	Elf32_Word shndx = sym->sec->idx;
+	Elf_Scn *s, *t = NULL;
+	int size, idx = sym->idx;
 
-	first_non_local = symtab->sh.sh_info;
-
-	sym = find_symbol_by_index(elf, first_non_local);
-	if (!sym) {
-		WARN("no non-local symbols !?");
-		return first_non_local;
-	}
+	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
+		size = sizeof(Elf32_Sym);
+	else
+		size = sizeof(Elf64_Sym);
 
 	s = elf_getscn(elf->elf, symtab->idx);
 	if (!s) {
@@ -625,79 +625,120 @@ static int elf_move_global_symbol(struct elf *elf, struct section *symtab,
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
+		symtab_data = elf_getdata(s, symtab_data);
+		if (t)
+			shndx_data = elf_getdata(t, shndx_data);
 
-	sym->idx = symtab->sh.sh_size / sizeof(sym->sym);
-	elf_dirty_reloc_sym(elf, sym);
+		if (!symtab_data) {
+			if (!idx) {
+				void *buf;
 
-	symtab->sh.sh_info += 1;
-	symtab->sh.sh_size += data->d_size;
-	symtab->changed = true;
+				symtab_data = elf_newdata(s);
+				if (t)
+					shndx_data = elf_newdata(t);
 
-	if (symtab_shndx) {
-		s = elf_getscn(elf->elf, symtab_shndx->idx);
-		if (!s) {
-			WARN_ELF("elf_getscn");
+				buf = calloc(1, size);
+				if (!buf) {
+					WARN("malloc");
+					return -1;
+				}
+
+				symtab_data->d_buf = buf;
+				symtab_data->d_size = size;
+				symtab_data->d_align = 1;
+				symtab_data->d_type = ELF_T_SYM;
+
+				symtab->sh.sh_size += size;
+				symtab->changed = true;
+
+				if (t) {
+					shndx_data->d_buf = &sym->sec->idx;
+					shndx_data->d_size = sizeof(Elf32_Word);
+					shndx_data->d_align = 4;
+					shndx_data->d_type = ELF_T_WORD;
+
+					symtab_shndx->sh.sh_size += 4;
+					symtab_shndx->changed = true;
+				}
+
+				break;
+			}
+
+			WARN("index out of range");
 			return -1;
 		}
 
-		shndx_data = elf_newdata(s);
-		if (!shndx_data) {
-			WARN_ELF("elf_newshndx_data");
+		if (!symtab_data->d_size) {
+			WARN("zero size data");
 			return -1;
 		}
 
-		shndx_data->d_buf = &sym->sec->idx;
-		shndx_data->d_size = sizeof(Elf32_Word);
-		shndx_data->d_align = 4;
-		shndx_data->d_type = ELF_T_WORD;
+		if (idx * size < symtab_data->d_size)
+			break;
 
-		symtab_shndx->sh.sh_size += 4;
-		symtab_shndx->changed = true;
+		idx -= symtab_data->d_size / size;
 	}
 
-	return first_non_local;
+	if (idx < 0) {
+		WARN("negative index");
+		return -1;
+	}
+
+	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
+		sym->sym.st_shndx = shndx;
+		if (!shndx_data)
+			shndx = 0;
+	} else {
+		sym->sym.st_shndx = SHN_XINDEX;
+		if (!shndx_data) {
+			WARN("no .symtab_shndx");
+			return -1;
+		}
+	}
+
+	if (!gelf_update_symshndx(symtab_data, shndx_data, idx, &sym->sym, shndx)) {
+		WARN_ELF("gelf_update_symshndx");
+		return -1;
+	}
+
+	return 0;
 }
 
 static struct symbol *
 elf_create_section_symbol(struct elf *elf, struct section *sec)
 {
 	struct section *symtab, *symtab_shndx;
-	Elf_Data *shndx_data = NULL;
-	struct symbol *sym;
-	Elf32_Word shndx;
+	Elf32_Word first_non_local, new;
+	struct symbol *sym, *old;
+	int size;
+
+	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
+		size = sizeof(Elf32_Sym);
+	else
+		size = sizeof(Elf64_Sym);
 
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
@@ -707,24 +748,42 @@ elf_create_section_symbol(struct elf *elf, struct section *sec)
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
+	new = symtab->sh.sh_size / size;
+
+	/*
+	 * Move the first global symbol, as per sh_info, into a new, higher
+	 * symbol index. This fees up a spot for a new local symbol.
+	 */
+	first_non_local = symtab->sh.sh_info;
+	old = find_symbol_by_index(elf, first_non_local);
+	if (old) {
+		old->idx = new;
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
+		new = first_non_local;
 	}
 
-	if (!gelf_update_symshndx(symtab->data, shndx_data, sym->idx, &sym->sym, shndx)) {
-		WARN_ELF("gelf_update_symshndx");
+	sym->idx = new;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoPCTEYjoPqE4ZxB%40hirez.programming.kicks-ass.net.
