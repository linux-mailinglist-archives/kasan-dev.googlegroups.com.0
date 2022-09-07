Return-Path: <kasan-dev+bncBC2ORX645YPRBQGU36MAMGQEC3ATQ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id C3EC15AF917
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 02:48:02 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id o14-20020a17090ab88e00b0020034a4415dsf5644677pjr.6
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 17:48:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662511681; cv=pass;
        d=google.com; s=arc-20160816;
        b=iadPQDM2+uEL3A6WIQteBhkD8AVkgnV+nguNohqVfjuRdlyj0Eif/Z38fk7Gf2HuyC
         TIgBviQ78epPzJXr3vSK91xRfMbScBUlKkIeB05NWhvjOJ9YJaAlsQ6R8iUlAnu1NAlF
         BnM7yGwGmmZ/hhhq/zDk19m8mocPfvX/KKUEpACAx5ghO6HPIeaaq2w6vB3ZsvWMIlVa
         XuxzY+8D+MafaAS1CK+4dFzROC17ODpO/PQp12S1CIKqIZMBES2wLAIOeM5aDoNnej2X
         bWm7rJl6/Rup90ieY6TJ+xL6S1fd1B285q80utGs86eB7bz2Wrn2sLICdlC3hKDpd85K
         od/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=p7B4g9GFzb9e/S6HvpIge4BMabwvwS72DZOZAb5pAIg=;
        b=ZPwZXLtyvsx5l3zqjh8xplXjfry2Q0RB6pI7o05p2nJb3kpwzjZgqfb1PpwkRPh4FN
         RJ1CILsn/ZswAU+ZgqLg1nX6SV2jAnldgGkFvlED50zS7mEK8jLMxHprmc71dG2sqDjM
         xLkvKrRKOIpdX3Tvdk9ZughWIg8gswAZ5ml+j8uBvsFXGAwI5baOnNWLMgNvkPJbMj5C
         bCDLoAWS5Xt0DrfpDdOho1J6ebKusHmLYrRdtqKMeU1rXMm0SiR2aZL5ZkxU2+Jl/BUJ
         ZhW4PYcGwiMloCrO1BQSZYwxLq7ECat/j9X6J5D8arriJdEt47hMIH7byTq9zkx4YlVK
         3u1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pR0smMM+;
       spf=pass (google.com: domain of samitolvanen@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=samitolvanen@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=p7B4g9GFzb9e/S6HvpIge4BMabwvwS72DZOZAb5pAIg=;
        b=SjYY7kXRQSSEfG5CSF1/1Cckl6rmTnHDVqYR5fit2+/f50gMtkj3n5Levn4tiVIWDp
         vndU5E4cmOjbZpzPsJLzcBsPFJDTH3wkGDGtwPtkkj7dAutufRNnp7wAft/HmCbo+WSF
         Lze50ajP1RUREN7FsPK4YG5RdC+dqkje1H80Cpj07E8cnRGl91CnlQbeNasrSZ6M00GA
         o6NEDeaPJgeTKrVnk2QDz1jWUw2n5Szq/K3/Tbhx+v4i/0rp/IPgiJkoPPK5DJEgrlyS
         jquMcYSMDYNtBWz+2uxAnRleshiGhNrlWGFAXQWZ6iKDDaaSOB++B1ahdqg/7WmUETpc
         RaQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=p7B4g9GFzb9e/S6HvpIge4BMabwvwS72DZOZAb5pAIg=;
        b=u7w16DFkLbAT++/0Q2M34DloG47/ELSxQac/C8nz/P7+97/pRLRyhUIT+il3/ZLpyI
         yePnrP/V2Nb9rQBm5F1zVFEA8ZVfd/6FaMPOpAFge+LYqkIhINBq6JO4idr6M6MpjXEe
         BszTfL9IUG2xr3ZTqqTw60TsZmX7Q15a6xvBXNpBM8QaIceI3ddhvL5xkuCeOyym+E7f
         NDqifVfO3VOe96DsQj0kvpAxlh6A5cJaJnXOEmbf5gq73X17ZHsG2BK2Jg4wyYLPUTPr
         WSpQ8iAY0mJ6IQCvEnD6GZcjbmdUKD2r/g4HsmG1LvXn2yTDNoY1XkYKDono/3xiuHAG
         AThA==
X-Gm-Message-State: ACgBeo1a5k8D5FpjICMiGT+KpCCNHCuqTZWDoOzYjQIJzr2/U5kdLT82
	mIU4z1JGlWzpFK3LNBwFzOo=
X-Google-Smtp-Source: AA6agR6Rb91OtCY+NEaoDuDyV78knnPZxXY0P6nAtakDvJOGmaBqt02H+Wlf1BKUqqSjE8/r5XyxTw==
X-Received: by 2002:a17:902:f7d2:b0:176:ca6b:eadb with SMTP id h18-20020a170902f7d200b00176ca6beadbmr1144424plw.173.1662511680900;
        Tue, 06 Sep 2022 17:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:240d:b0:16d:4224:4877 with SMTP id
 e13-20020a170903240d00b0016d42244877ls10522907plo.4.-pod-prod-gmail; Tue, 06
 Sep 2022 17:48:00 -0700 (PDT)
X-Received: by 2002:a17:902:d484:b0:171:3cbc:7c6 with SMTP id c4-20020a170902d48400b001713cbc07c6mr1293002plg.85.1662511680079;
        Tue, 06 Sep 2022 17:48:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662511680; cv=none;
        d=google.com; s=arc-20160816;
        b=Y6kYv+51LCtw7wM2RwVJR5F3++chnzYK+8E4XhbyVIf6aIU1jtCa5wdwEFSA4BubBU
         T0YdFfK1lO9pYKsT057zw5U8uQLxQtRIuyWbFhBxK+49VQScvgvJ5Z7T8De2LlYewc4H
         bPhRKMmyldVeqBHky1X8MLJPZ09FUuYTQuJhWuodJ8jiFAEqqAAFmQfyni03IXApuipn
         eRirZX9kwv+LHhzY2yPwXPRX3fPZINBr5QqgnRZrbulgSPqYfsHvnIFvgec37kW8fCeW
         M0Yi7dlg3BWj7WfyBbVNDNtw+ApmOkKuHsaMkOZK8HGDJl+e9rNkAcj2JKs3yDUxgnC3
         4jOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hxTBhCI0F5j/2VZXRiH27pSDCjgcW9IAx9MdqUjicTA=;
        b=ntFra6j4BBeE/ZUgHuH1P2Tm5LpeD59qvsYYC5YEdeVv5bSbiU5mvap8fLJ4WjfX2+
         DFJWaOgHAhBFCbB48rEIk0eSA19LPbMJDlrwezIgC4A5Io5b3On5oxayS3zKxniu/req
         zW8HCxfGBH1hlfJUKQmRivsDWPqbR5f5hm1VcpZCcmLgCviyVysQEHyjBcjmX5BgS9th
         dKD27kET5RbTGImT6EeB4vzTa9DcjsThx8MDNCY7umzCRFBXa/AqZi3nxIHbTFx01ur9
         GT1yWqNKq8ZKuK9FSMJIuTHHnINsQlFazAeR+7k1g5G7Xp25F2NT5AS/oP8sHWCOR60I
         SNaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pR0smMM+;
       spf=pass (google.com: domain of samitolvanen@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=samitolvanen@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe33.google.com (mail-vs1-xe33.google.com. [2607:f8b0:4864:20::e33])
        by gmr-mx.google.com with ESMTPS id a16-20020a621a10000000b00537a63cf17dsi977479pfa.3.2022.09.06.17.48.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Sep 2022 17:48:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of samitolvanen@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) client-ip=2607:f8b0:4864:20::e33;
Received: by mail-vs1-xe33.google.com with SMTP id d126so13346098vsd.13
        for <kasan-dev@googlegroups.com>; Tue, 06 Sep 2022 17:48:00 -0700 (PDT)
X-Received: by 2002:a05:6102:304e:b0:397:6b53:5f81 with SMTP id
 w14-20020a056102304e00b003976b535f81mr360723vsa.80.1662511679176; Tue, 06 Sep
 2022 17:47:59 -0700 (PDT)
MIME-Version: 1.0
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X> <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net> <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble> <20220518074152.GB10117@worktop.programming.kicks-ass.net>
 <20220518173604.7gcrjjum6fo2m2ub@treble> <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
In-Reply-To: <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
From: "'Sami Tolvanen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Sep 2022 17:47:23 -0700
Message-ID: <CABCJKueB-tZmxESGP_W9JUghu-6y1Dj1DeahRsGb3bOUttctMA@mail.gmail.com>
Subject: Re: [PATCH] objtool: Fix symbol creation
To: Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samitolvanen@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pR0smMM+;       spf=pass
 (google.com: domain of samitolvanen@google.com designates 2607:f8b0:4864:20::e33
 as permitted sender) smtp.mailfrom=samitolvanen@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sami Tolvanen <samitolvanen@google.com>
Reply-To: Sami Tolvanen <samitolvanen@google.com>
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

On Wed, May 18, 2022 at 3:10 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, May 18, 2022 at 10:36:04AM -0700, Josh Poimboeuf wrote:
> > On Wed, May 18, 2022 at 09:41:52AM +0200, Peter Zijlstra wrote:
> > > +static int elf_update_symbol(struct elf *elf, struct section *symtab,
> > > +                        struct section *symtab_shndx, struct symbol *sym)
> > >  {
> > > -   Elf_Data *data, *shndx_data = NULL;
> > > -   Elf32_Word first_non_local;
> > > -   struct symbol *sym;
> > > -   Elf_Scn *s;
> > > -
> > > -   first_non_local = symtab->sh.sh_info;
> > > -
> > > -   sym = find_symbol_by_index(elf, first_non_local);
> > > -   if (!sym) {
> > > -           WARN("no non-local symbols !?");
> > > -           return first_non_local;
> > > -   }
> > > +   Elf_Data *symtab_data = NULL, *shndx_data = NULL;
> > > +   Elf64_Xword entsize = symtab->sh.sh_entsize;
> > > +   Elf32_Word shndx = sym->sec->idx;
> >
> > So if it's a global UNDEF symbol then I think 'sym->sec' can be NULL and
> > this blows up?
>
> Oh indeed, sym->sec ? sym->sec->idx : SHN_UNDEF it is.

elf_update_symbol seems to be a bit broken even after this. I noticed
it converts SHN_ABS symbols into SHN_UNDEF, which breaks some KCFI
builds. In fact, the function drops all the special st_shndx values
except SHN_XINDEX.

Specifically, read_symbols sets sym->sec to find_section_by_index(elf,
0) for all SHN_UNDEF and special st_shndx symbols, which means
sym->sec is non-NULL and sym->sec->idx is always 0 (= SHN_UNDEF) for
these symbols. As elf_update_symbol doesn't look at the actual
st_shndx value, it ends up marking the symbols undefined.

This quick hack fixes the issue for me, but I'm not sure if it's the
cleanest solution. Any thoughts?

diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
index c25e957c1e52..7e24b09b1163 100644
--- a/tools/objtool/elf.c
+++ b/tools/objtool/elf.c
@@ -619,6 +619,11 @@ static int elf_update_symbol(struct elf *elf,
struct section *symtab,
        Elf64_Xword entsize = symtab->sh.sh_entsize;
        int max_idx, idx = sym->idx;
        Elf_Scn *s, *t = NULL;
+       bool is_special_shndx = sym->sym.st_shndx >= SHN_LORESERVE &&
+                               sym->sym.st_shndx != SHN_XINDEX;
+
+       if (is_special_shndx)
+               shndx = sym->sym.st_shndx;

        s = elf_getscn(elf->elf, symtab->idx);
        if (!s) {
@@ -704,7 +709,7 @@ static int elf_update_symbol(struct elf *elf,
struct section *symtab,
        }

        /* setup extended section index magic and write the symbol */
-       if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
+       if ((shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) || is_special_shndx) {
                sym->sym.st_shndx = shndx;
                if (!shndx_data)
                        shndx = 0;

Sami

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABCJKueB-tZmxESGP_W9JUghu-6y1Dj1DeahRsGb3bOUttctMA%40mail.gmail.com.
