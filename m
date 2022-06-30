Return-Path: <kasan-dev+bncBC6OLHHDVUOBBMNN6WKQMGQENIVGBMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0339A5613BC
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 09:54:26 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id a1-20020adfbc41000000b0021b90d6d69asf2851353wrh.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 00:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656575665; cv=pass;
        d=google.com; s=arc-20160816;
        b=NHox5BPfMMQmh4RIMbdO6004IxCgrlljZ5WtsQKM06esm/6IWyMqdKNltLP2u9rUCx
         ysCsYmaf0gQLCilmzBrs+4d29SJByK9Q7XWoBBCuZFCyHcO7qeXuNkt489WM3sDVVgHE
         V5c6hGDYTuYjxZYNTIIXMUNBSdqKFWrjlhiisRF0eoEutcdHRdgNLp5D7SUl5CCf8Yp1
         iNEsMFXTkU3vfuO3zm14mjPOpaNlqjUIaPApjgPb4wooYaXeP9isxBTtFte33p+I1SIT
         rejUpEP+F8T3E0r6DfrWdST7y7lEU7b1ZeJbTCgeASbk6MdzR0j3U7s5uSWzBkpgo1Lw
         jUhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sngtd1aizMKsSs/I5BA1jcfoCY1e0drwMv6Z+CjUu/I=;
        b=0X5+Bzo3Dxi+KntUubgYty8pwEp/fWLI01w5Gm+ng2kyEe0mEe6Bhs57lduT3FX5bc
         QL56VCggTSKb/Ctm+d+K9orpAu720/R2mfF4q52B+mD+61RfGU9yC+8ZodnO4I3v30KC
         2lofsL0bvUiiZyC3KOW4c7jbqR/mQiBFJJacbemPZUBDX5zcsxbWx5hJqzcUEHomzjNG
         dRReGVuUjhxpjejTIRj+C1NBbIX0P+LkvsqnG1PWHtgmBA28k57CC9WciRVCyYNjPr4w
         k9bPuW9A6zl3GDJc+U5K5O38JIy6QwcP4lZtOGQp94h2/EEQuDtGK07+Zi7wcoxje5Fy
         zSbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jFheuZvZ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sngtd1aizMKsSs/I5BA1jcfoCY1e0drwMv6Z+CjUu/I=;
        b=q2sy4LCk1DN9wJnTVyecQLgnjd3meV0aqsAvTNAB+qzTa3xgGg88Ip5wSnK2AXTe0a
         hCEOrH40vlfdBb8o8fpwuBNC9y7OA+wf54l9ICvc0WEUNe8ohYE3Vou3Gxp7/KYcxrrD
         K3qyOxL9InxA+WQIeIuGp+GaK0iVaEGnVqaKXkTbwlzLcSzPuM76E/WrVSf8hPyjl4hX
         lQgKauXySzO89Rvywq1Lty5T7S74TH417jU6aDleO5By6U1XCkZUAEUkBkYeMuD1n19y
         mhXYeZR2H4SGKsbre4hz2irTGY9pkuJoR4B6Fad6sGnlDtNuyx8GU2YU0BZ1BbgJ6Unp
         TT0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sngtd1aizMKsSs/I5BA1jcfoCY1e0drwMv6Z+CjUu/I=;
        b=YZ+uKJWdasCHnzw9Mp0PsJTTUvKIDYsCw9rJeei5GH6Z5IUzwdVtGtglH+uBHVMwcB
         msftQ0mBPgg5BS3YhgRuxTXRkvoP5NsXzcMbv7nMIFqlueneqqgfnZbOV4S5GJHM2z+P
         bqSitELK9jneRBnItPcA8VdHlzzl3TjaHPrna6Rs8XSolYWAWanC7d0cgzcUcUIC5hYE
         RL3az7zCQB6KjE7yDHQxyD6gGTHxi9hYyGltTNLS1owJ4JVOySIWT7zHcf4HPMeUtXGN
         h0RrmB8muaNcomBdIlGkKO0mFUQrBwc1pOjRtZX7g81TQFvwZ0nW/v8FseF8N1JmULSh
         I+Gg==
X-Gm-Message-State: AJIora/HURvvK/9N8JQizTORM+mmmgeGmTqVkgFnHD9oV50F9Sy4Dfd+
	6hoJpIyrpqzsnQoak0cFqSE=
X-Google-Smtp-Source: AGRyM1sAAc+Z5oJK7Re7Vu8vtptGnQuBYG9Tb7IKcW7PtSrxLPGxm55RCbh+mBdNpVWTu8QONxsRtg==
X-Received: by 2002:a05:6000:156f:b0:21b:a702:d595 with SMTP id 15-20020a056000156f00b0021ba702d595mr7262309wrz.341.1656575665475;
        Thu, 30 Jun 2022 00:54:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls1187805wms.1.gmail; Thu, 30 Jun 2022
 00:54:24 -0700 (PDT)
X-Received: by 2002:a05:600c:3d96:b0:3a1:8681:cc80 with SMTP id bi22-20020a05600c3d9600b003a18681cc80mr25727wmb.192.1656575664198;
        Thu, 30 Jun 2022 00:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656575664; cv=none;
        d=google.com; s=arc-20160816;
        b=NdrAARyc1lG3YmCPacvmx7Is2ws9bXiW3LBTrIdvtA/TvQq3JsxIINS3JXI++GEEq2
         tR/DVhWb8FaBOf+WyTmYA/IRFkC9azTmhqUr+aCjP8aZoRL0WAIGD1H//8pb52VtDlLu
         mZSiJl5IdmIVWuX5OSSdKGmdj0BlPPpEs7K/UmuYhJvOLK4izXj4Scqkk0bOuSUBq4ZY
         xl5LX68aoTt7DF2IqPTrJn1i9S4PyrmHmIKMYfkOWjwF2Nd3XO2dfGRcOZT2H85fzKTd
         TXcqePVJ0o1FHCdC1H4BYzueBpx/roBiLVICe+AEFQDzhJatj+V2Nfh3B10C6V82/lMu
         YQMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CVxAPpcHZB3N5YI3B1p3UK7UedU4fE2ZkTtEMvdDPuc=;
        b=pKsEXSkiUrcGlNUlYEPfKOIrmPl5m1Iivwx5DcTYjAjKXLiX7SXSSEfZxAboWIg4Wg
         Mcbeo0h09oad1pSv8TDGhhhoEV71IhwF50iLvWlkEFGvtNeG/KzcPFKXRwXmbqs3qI4E
         jezuDnzq1aSC5mssXkUcuUQfiociHvzgj+yzuM6ka8fxu+OaJt8At9thW54V5YtnMI/p
         l15LxbMmmLfVL1iGZT6XHDsW4EFs7dRf5YOvbBbjHU3QgIq+S2a4AeFjoZJ2d1BULTxV
         YIABUdL9gpbCO4EQfGQhV8SrpXRJxlSD/CLQpdVIt/XaQmEndoNrk5libQ1ZjI/AxESl
         /Puw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jFheuZvZ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si638099wrr.7.2022.06.30.00.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 00:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id m6-20020a05600c3b0600b003a0489f412cso1764046wms.1
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 00:54:24 -0700 (PDT)
X-Received: by 2002:a05:600c:4fd0:b0:39c:6565:31a5 with SMTP id
 o16-20020a05600c4fd000b0039c656531a5mr10297511wmq.60.1656575663609; Thu, 30
 Jun 2022 00:54:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220527185600.1236769-1-davidgow@google.com> <20220527185600.1236769-2-davidgow@google.com>
 <CA+fCnZe63vugPRbD3fVNGnTWbSvjd08g8coG3D71-=NtqpjOvQ@mail.gmail.com>
In-Reply-To: <CA+fCnZe63vugPRbD3fVNGnTWbSvjd08g8coG3D71-=NtqpjOvQ@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 15:54:12 +0800
Message-ID: <CABVgOS=hW0Paz2EwV0dvJQLM9cT-YNBzEXmUJZZ8Db5PZr-5Qg@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um <linux-um@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000ffddaf05e2a59308"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jFheuZvZ;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

--000000000000ffddaf05e2a59308
Content-Type: text/plain; charset="UTF-8"

On Tue, May 31, 2022 at 2:03 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Fri, May 27, 2022 at 8:56 PM David Gow <davidgow@google.com> wrote:
> >
> > From: Patricia Alfonso <trishalfonso@google.com>
> >
> > Make KASAN run on User Mode Linux on x86_64.
> >
> > The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB
> > of shadow memory to the location defined by KASAN_SHADOW_OFFSET.
> > kasan_init() utilizes constructors to initialize KASAN before main().
> >
> > The location of the KASAN shadow memory, starting at
> > KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> > option. UML uses roughly 18TB of address space, and KASAN requires 1/8th
> > of this. The default location of this offset is 0x100000000000, which
> > keeps it out-of-the-way even on UML setups with more "physical" memory.
> >
> > For low-memory setups, 0x7fff8000 can be used instead, which fits in an
> > immediate and is therefore faster, as suggested by Dmitry Vyukov. There
> > is usually enough free space at this location; however, it is a config
> > option so that it can be easily changed if needed.
> >
> > Note that, unlike KASAN on other architectures, vmalloc allocations
> > still use the shadow memory allocated upfront, rather than allocating
> > and free-ing it per-vmalloc allocation.
> >
> > Also note that, while UML supports both KASAN in inline mode
> > (CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
> > not support both at the same time.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> > Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> > Signed-off-by: David Gow <davidgow@google.com>
>
> Hi David,
>
> Thanks for working on this!
>
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index a4f07de21771..c993d99116f2 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -295,9 +295,29 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> >                 return 0;
> >
> >         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> > -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> >         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> > -       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> > +
> > +       /*
> > +        * User Mode Linux maps enough shadow memory for all of physical memory
> > +        * at boot, so doesn't need to allocate more on vmalloc, just clear it.
>
> Should this say "for all of _virtual_ memory"?
>
> Otherwise, this is confusing. All KASAN-enabled architectures map
> shadow for physical memory. And they still need map shadow for
> vmalloc() separately. This is what kasan_populate_vmalloc() is for.
>

Yup, this was a mistake on my part: the original RFC for KASAN/UML
only allocated enough shadow memory to cover physical memory, but it
was changed in v1 (which I'd forgotten).

I've updated the comment in v3:
https://lore.kernel.org/lkml/20220630074757.2739000-2-davidgow@google.com/

> > +        *
> > +        * If another architecture chooses to go down the same path, we should
> > +        * replace this check for CONFIG_UML with something more generic, such
> > +        * as:
> > +        * - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
> > +        * - or, a way of having architecture-specific versions of these vmalloc
> > +        *   and module shadow memory allocation options.
>
> I think this part above and the first sentence below belong to the
> commit changelog, not to a comment.
>

While I think there's _some_ sense in leaving this in the comment (as
a bit of a reminder / TODO), given that the commit changelog is more
ephemeral, I've moved it to the commit message for v3. This will be
easy to find via git blame, while not cluttering the actual file, so
seems an okay spot for it.

Cheers,
-- David



> > +        *
> > +        * For the time being, though, this check works. The remaining CONFIG_UML
> > +        * checks in this file exist for the same reason.
> > +        */
> > +       if (IS_ENABLED(CONFIG_UML)) {
> > +               __memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> > +               return 0;
> > +       }
> > +
> > +       shadow_start = PAGE_ALIGN_DOWN(shadow_start);
> > +       shadow_end = PAGE_ALIGN(shadow_end);
> >
> >         ret = apply_to_page_range(&init_mm, shadow_start,
> >                                   shadow_end - shadow_start,
> > @@ -466,6 +486,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
> >
> >         if (shadow_end > shadow_start) {
> >                 size = shadow_end - shadow_start;
> > +               if (IS_ENABLED(CONFIG_UML)) {
> > +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> > +                       return;
> > +               }
> >                 apply_to_existing_page_range(&init_mm,
> >                                              (unsigned long)shadow_start,
> >                                              size, kasan_depopulate_vmalloc_pte,
> > @@ -531,6 +555,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> >         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> >                 return -EINVAL;
> >
> > +       if (IS_ENABLED(CONFIG_UML)) {
> > +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> > +               return 0;
> > +       }
> > +
> >         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> >                         shadow_start + shadow_size,
> >                         GFP_KERNEL,
> > @@ -554,6 +583,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> >
> >  void kasan_free_module_shadow(const struct vm_struct *vm)
> >  {
> > +       if (IS_ENABLED(CONFIG_UML))
> > +               return;
> > +
> >         if (vm->flags & VM_KASAN)
> >                 vfree(kasan_mem_to_shadow(vm->addr));
> >  }
> > --
> > 2.36.1.124.g0e6072fb45-goog
> >
>
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DhW0Paz2EwV0dvJQLM9cT-YNBzEXmUJZZ8Db5PZr-5Qg%40mail.gmail.com.

--000000000000ffddaf05e2a59308
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIPnwYJKoZIhvcNAQcCoIIPkDCCD4wCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggz5MIIEtjCCA56gAwIBAgIQeAMYYHb81ngUVR0WyMTzqzANBgkqhkiG9w0BAQsFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0yOTAzMTgwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFIzIFNNSU1FIENBIDIwMjAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvLe9xPU9W
dpiHLAvX7kFnaFZPuJLey7LYaMO8P/xSngB9IN73mVc7YiLov12Fekdtn5kL8PjmDBEvTYmWsuQS
6VBo3vdlqqXZ0M9eMkjcKqijrmDRleudEoPDzTumwQ18VB/3I+vbN039HIaRQ5x+NHGiPHVfk6Rx
c6KAbYceyeqqfuJEcq23vhTdium/Bf5hHqYUhuJwnBQ+dAUcFndUKMJrth6lHeoifkbw2bv81zxJ
I9cvIy516+oUekqiSFGfzAqByv41OrgLV4fLGCDH3yRh1tj7EtV3l2TngqtrDLUs5R+sWIItPa/4
AJXB1Q3nGNl2tNjVpcSn0uJ7aFPbAgMBAAGjggGKMIIBhjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l
BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHzM
CmjXouseLHIb0c1dlW+N+/JjMB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHsGCCsG
AQUFBwEBBG8wbTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
MzA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvcm9vdC1y
My5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIz
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
z/tQRXr3iPeVmZCr7nttMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAx+EQjLATc/sze
VoZkH7OLz+/no1+y31x4BQ3wjW7lKfay9DAAVym896b7ECttSo95GEvS7pYMikzud57WypK7Bjpi
ep8YLarLRDrvyyvBuYtyDrIewkuASHtV1oy5E6QZZe2VOxMm6e2oJnFFjbflot4A08D3SwqDwV0i
OOYwT0BUtHYR/3903Dmdx5Alq+NDvUHDjozgo0f6oIkwDXT3yBV36utQ/jFisd36C8RD5mM+NFpu
3aqLXARRbKtxw29ErCwulof2dcAonG7cd5j+gmS84sLhKU+BhL1OQVXnJ5tj7xZ5Ri5I23brcwk0
lk/gWqfgs3ppT9Xk7zVit9q8MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCA8
dJASzRdZfOM9mtHBhqflP7aBrs0/xvVtIUdMC3r85DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA2MzAwNzU0MjRaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAYakGfvHtyZ4mETpJfNlS
njRUqpN1/M/fQW/N1GCxRQqh/L56zkSnqSGAmJgSpYO5ZAKXMLyzMybVDqz/KV06EuuDObU0ASGf
NpnEUXAPEb8Z3Lw1b0vhGfzBpI/VLS+9tCJ+aiY6VruXKZzs12fdGctTJQyvoUDgAVdEurtrlITa
ZNMiqQMQ9oTdUCDY0Hjn33WAehp1wX2zm87b5yaLFvT3dNpoTUOc9I73wBwJHJldacAzY+sRsRHF
JkFIz5S3tn7SypCbsfHfxpmiLjwnbvAID3xdaYMVh5B1o5caNzVe/uQqLP9pTvRPUtYy1Y6qBiKs
w0Hn+2N9k/Ht945f8Q==
--000000000000ffddaf05e2a59308--
