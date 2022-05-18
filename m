Return-Path: <kasan-dev+bncBDBK55H2UQKRBAGGSKKAMGQE6EGBL5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 89AC152B3AF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:40:49 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id e10-20020a05651236ca00b00474337bbe36sf731107lfs.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:40:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652859649; cv=pass;
        d=google.com; s=arc-20160816;
        b=uEaL35XTIquD5qgmeI79wYf/LdBKUMZsrqFjCN1iiab+0TasliWWnYhKNTwbqyGs1d
         xwuvb0yWRHXkihM+dmwPXevFoZ4eGr5W1msppUEmi4LJ/4hZFLN9rC++z2llwnmeycni
         PuYPOJu4+QZWIqQNFne/qAyC4zm27/KVIAh78sQzbe0XMV5CUFPT8aZWjvx8LrS59aEE
         24cBxR4ouXz5yK3PGgCtBKEMRLDEnKqbtiseWYy5QF2yukK9XvW4vPp3cP8ijDsRn0AV
         jmwaBK+UzgOEN566jEgDFXPGJCngPqwx1l5M/baFrUZWM556DS2qdAG9Ztq7xBVOX8NI
         xHRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lkYTlvdqLVXiqjm7Cwol/mMppen7UAC19qcYyT5DY58=;
        b=U7C0gojcXNKtSAOYq+dnKE5rT51vWiLMVbkNoEVIHoXgeyngTjmEAf33B4fIv1WaQs
         HPTNcxcJloN6QCgApvggvA1LO/unh45xbJniOrxS2IkMkDnoxY8OpE3zzxrR+JAfhtMe
         X9yeToXhiCThjFNnqo13JQhwTGyCeRkTmoRxOyxO1EkcC1cbAQR3sYRAM0JGmiPpTW7E
         jyZ6mE5NKAba+DjjVB4CzOt6uIlg9RbcwWPZj8pMIArQzHr/ePU9G68T3B2ux+ORyewA
         YRAcWDTHE8AB7VsWNupyhuh2lsUZf3IDYXZQ/LRDPqi1lrDpoP9n8DUru1LsUeb1/fvO
         P+EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="lNeeEe/z";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lkYTlvdqLVXiqjm7Cwol/mMppen7UAC19qcYyT5DY58=;
        b=DwS9daqxVxl8ysdX00iqQLiljm0gRDG8KFc5v25fiYb46CYX+HB8qzsYmAsk6Z3yzY
         7/x76uPOnVkfgsNnrK30zCcQTzjXh4Sqbz2NdRePeokq8S6MgaC2ekIB9FuenoAL0jf6
         yBC78ZS14EIGi1O+XDDmuVvJUdJfFV9RlIoRq8DDM+m0uFmgOXeSHLwZaFASDQrRj8FU
         BllEw/Vy0NnETRyrgCZIdWYTaZMt4YVyNuUnFk/EJJpzJyu/ypvCf0+jcGUnYhuMiUxl
         9ettelnpYtyXaCjiyE0bYk3tzmFNiMrfpR58bL44AQ2m/FXzBpkH4bJmFa/P9Lyxx2es
         cWDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lkYTlvdqLVXiqjm7Cwol/mMppen7UAC19qcYyT5DY58=;
        b=Lb8vR6jtPwUBAu/wW9Oj/qEcHxJ2bHiC7zyhrH3I2atR9dyvgJfa4xRLGoo1fjH4dG
         h6DY282zIhTR/HNXrZUiIjrOEjbPDlq+ovWHqV1JCMnpGbYj3AMZlv1ugdIrQX0QR1QW
         8KG3nQBCSavTBvyW4x4PI1jv3Uvzt/qezwp4ofC27neql9hCYSSuGlo0Nd2XYMsCMJcd
         EDnGAhiNPqFbooghmXLKtTcbQIK2Oc4puX3Qd89zDGGMPuyTMickMgOvHzF4MIYKyKmb
         5Ej71Vf6UHSKpsnnOItXcfacYSJNypvCrYtYPF5PRLfLLDpgv2gc3MguUSnbm8IkO2ok
         SsYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530StN8HUyhUK7gXyVieg9IT+Tu3ry8ENTQXh7dxKVVSgpyN3dCX
	aGXDpgy7qDZRQb3gyN1ex1A=
X-Google-Smtp-Source: ABdhPJxEwzyL18dN2pkxXzd4Xhk+D9zByqkPJvY+M0rXePGNu+/xK8mo9VQBVVa0RSMSlWjiBCUeGQ==
X-Received: by 2002:a2e:9953:0:b0:24f:2926:6a23 with SMTP id r19-20020a2e9953000000b0024f29266a23mr16571783ljj.312.1652859648817;
        Wed, 18 May 2022 00:40:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls13410552lfb.1.gmail; Wed, 18 May 2022
 00:40:47 -0700 (PDT)
X-Received: by 2002:a05:6512:168d:b0:471:6cb9:c20f with SMTP id bu13-20020a056512168d00b004716cb9c20fmr19683006lfb.229.1652859647362;
        Wed, 18 May 2022 00:40:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652859647; cv=none;
        d=google.com; s=arc-20160816;
        b=BaMSSuI3Tqw/2sUcow5+TWZqqHp4KDwGS4l895zdc9Ujhyij09lmEqaqLIgrfstDXo
         b+sDVtLPwq46jJ8e/9SBmMHHEbs9xqK7/JU4Ch8RaRBeAPhr/CXxtBWKX5S0xzEhrM5d
         R4iffDY1mcSAiEUpkDfAS6U4O1Xe8LPA8YVJinG3c66wxr91T2tJB99MU87kczxe5RrX
         X2FPcpmhwtvVc7kLfFl2bafXWmnjwtB7bG8HVZBvc/f6BM5hXewwh3Gq69vohaWyz4d1
         Kb62z0w7HXrrBgCV4jalTdeRoa5FedNKsel4rmdEgekXf/PLz3Rx4LMUJPNXa7IpiN6Q
         sNRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=P7RoC/DyaIBUrw0WHH4NMmGnt1nOfh1Pg+yXcFOgWnU=;
        b=sGPdsSmnSdhTYSRZ1PGa50Iv+EhSuSUnAiGTu6mcW4Xx7krwf4RJNUPm6mBfok1s/c
         qHYRpS7ZRLxRUJLL3AH7MlC6idg9bBl1Mx/DbKFoO0T6IHO/yot4wOutrnXqjn6YNXQJ
         MJHmNLNDnoMQPpKYfjIDstlBnB4knexgSL+EzHmROaFmlZbLreQjrYhKlggUu3DIwyrs
         m+9ZxHzxS5zoL0CBp+XJWUN1BdskMiC/Qn4MvosZhHqpDi6+p05rTIgJnX9hLCrCqTr5
         vSmjEGH6Y6wi8sJlf0+XB6kiz5fvHC+TpJZCA1Cw29L6UC3L8YlRr4HatfD4Twobr/Dq
         C/qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="lNeeEe/z";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id w4-20020a2e9bc4000000b0024f304af5b0si55962ljj.7.2022.05.18.00.40.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 00:40:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrEIW-001Tr2-MJ; Wed, 18 May 2022 07:40:45 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 85A6098119B; Wed, 18 May 2022 09:40:42 +0200 (CEST)
Date: Wed, 18 May 2022 09:40:42 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518074042.GA10117@worktop.programming.kicks-ass.net>
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
 header.i=@infradead.org header.s=desiato.20200630 header.b="lNeeEe/z";
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

On Tue, May 17, 2022 at 06:24:29PM -0700, Josh Poimboeuf wrote:
> On Tue, May 17, 2022 at 05:42:04PM +0200, Peter Zijlstra wrote:
> > +	for (;;) {
> > +		symtab_data = elf_getdata(s, symtab_data);
> > +		if (t)
> > +			shndx_data = elf_getdata(t, shndx_data);
> >  
> > -	sym->idx = symtab->sh.sh_size / sizeof(sym->sym);
> > -	elf_dirty_reloc_sym(elf, sym);
> > +		if (!symtab_data) {
> > +			if (!idx) {
> > +				void *buf;
> 
> I'm confused by whatever this is doing, how is !symtab_data possible,
> i.e. why would symtab not have data?
> 
> >  elf_create_section_symbol(struct elf *elf, struct section *sec)
> >  {
> >  	struct section *symtab, *symtab_shndx;
> > -	Elf_Data *shndx_data = NULL;
> > -	struct symbol *sym;
> > -	Elf32_Word shndx;
> > +	Elf32_Word first_non_local, new;
> > +	struct symbol *sym, *old;
> > +	int size;
> > +
> > +	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
> > +		size = sizeof(Elf32_Sym);
> > +	else
> > +		size = sizeof(Elf64_Sym);
> 
> This should probably be called 'entsize' and I think you can just get it
> from symtab->sh.sh_entsize.
> 
> > +	/*
> > +	 * Either way, we added a LOCAL symbol.
> > +	 */
> > +	symtab->sh.sh_info += 1;
> > +
> >  	elf_add_symbol(elf, sym);
> 
> Not sure if it matters here, but elf_add_symbol() doesn't set sym->alias
> and sym->pv_target, and both of those are unconditionally initialized in
> read_symbols().  Should elf_add_symbol() be changed to initialize them?



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

@@ -604,7 +605,8 @@ static void elf_dirty_reloc_sym(struct e

 /*
  * The libelf API is terrible; gelf_update_sym*() takes a data block relative
- * index value. As such, iterate the data blocks and adjust index until it fits.
+ * index value, *NOT* the symbol index. As such, iterate the data blocks and
+ * adjust index until it fits.
  *
  * If no data block is found, allow adding a new data block provided the index
  * is only one past the end.
@@ -613,14 +615,10 @@ static int elf_update_symbol(struct elf
 			     struct section *symtab_shndx, struct symbol *sym)
 {
 	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
+	Elf64_Xword entsize = symtab->sh.sh_entsize;
 	Elf32_Word shndx = sym->sec->idx;
 	Elf_Scn *s, *t = NULL;
-	int size, idx = sym->idx;
-
-	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
-		size = sizeof(Elf32_Sym);
-	else
-		size = sizeof(Elf64_Sym);
+	int max_idx, idx = sym->idx;

 	s = elf_getscn(elf->elf, symtab->idx);
 	if (!s) {
@@ -637,11 +635,14 @@ static int elf_update_symbol(struct elf
 	}

 	for (;;) {
+		/* get next data descriptor for the relevant sections */
 		symtab_data = elf_getdata(s, symtab_data);
 		if (t)
 			shndx_data = elf_getdata(t, shndx_data);

+		/* end-of-list */
 		if (!symtab_data) {
+			/* if @idx == 0, it's the next contiguous entry, create it */
 			if (!idx) {
 				void *buf;

@@ -649,53 +650,60 @@ static int elf_update_symbol(struct elf
 				if (t)
 					shndx_data = elf_newdata(t);

-				buf = calloc(1, size);
+				buf = calloc(1, entsize);
 				if (!buf) {
 					WARN("malloc");
 					return -1;
 				}

 				symtab_data->d_buf = buf;
-				symtab_data->d_size = size;
+				symtab_data->d_size = entsize;
 				symtab_data->d_align = 1;
 				symtab_data->d_type = ELF_T_SYM;

-				symtab->sh.sh_size += size;
+				symtab->sh.sh_size += entsize;
 				symtab->changed = true;

 				if (t) {
 					shndx_data->d_buf = &sym->sec->idx;
 					shndx_data->d_size = sizeof(Elf32_Word);
-					shndx_data->d_align = 4;
+					shndx_data->d_align = sizeof(Elf32_Word);
 					shndx_data->d_type = ELF_T_WORD;

-					symtab_shndx->sh.sh_size += 4;
+					symtab_shndx->sh.sh_size += sizeof(Elf32_Word);
 					symtab_shndx->changed = true;
 				}

 				break;
 			}

+			/* we don't do holes in symbol tables */
 			WARN("index out of range");
 			return -1;
 		}

+		/* empty blocks should not happen */
 		if (!symtab_data->d_size) {
 			WARN("zero size data");
 			return -1;
 		}

-		if (idx * size < symtab_data->d_size)
+		/* is this the right block? */
+		max_idx = symtab_data->d_size / entsize;
+		if (idx < max_idx)
 			break;

-		idx -= symtab_data->d_size / size;
+		/* adjust index and try again */
+		idx -= max_idx;
 	}

+	/* something went side-ways */
 	if (idx < 0) {
 		WARN("negative index");
 		return -1;
 	}

+	/* setup extended section index magic and write the symbol */
 	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
 		sym->sym.st_shndx = shndx;
 		if (!shndx_data)
@@ -720,14 +728,8 @@ static struct symbol *
 elf_create_section_symbol(struct elf *elf, struct section *sec)
 {
 	struct section *symtab, *symtab_shndx;
-	Elf32_Word first_non_local, new;
+	Elf32_Word first_non_local, new_idx;
 	struct symbol *sym, *old;
-	int size;
-
-	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
-		size = sizeof(Elf32_Sym);
-	else
-		size = sizeof(Elf64_Sym);

 	symtab = find_section_by_name(elf, ".symtab");
 	if (symtab) {
@@ -752,16 +754,15 @@ elf_create_section_symbol(struct elf *el
 	// st_value 0
 	// st_size 0

-	new = symtab->sh.sh_size / size;
-
 	/*
 	 * Move the first global symbol, as per sh_info, into a new, higher
 	 * symbol index. This fees up a spot for a new local symbol.
 	 */
 	first_non_local = symtab->sh.sh_info;
+	new_idx = symtab->sh.sh_size / symtab->sh.sh_entsize;
 	old = find_symbol_by_index(elf, first_non_local);
 	if (old) {
-		old->idx = new;
+		old->idx = new_idx;

 		hlist_del(&old->hash);
 		elf_hash_add(symbol, &old->hash, old->idx);
@@ -773,10 +774,10 @@ elf_create_section_symbol(struct elf *el
 			return NULL;
 		}

-		new = first_non_local;
+		new_idx = first_non_local;
 	}

-	sym->idx = new;
+	sym->idx = new_idx;
 	if (elf_update_symbol(elf, symtab, symtab_shndx, sym)) {
 		WARN("elf_update_symbol");
 		return NULL;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518074042.GA10117%40worktop.programming.kicks-ass.net.
