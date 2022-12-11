Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZF53GOAMGQEKWLJMJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id C21C16496D9
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 23:51:17 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id d130-20020a1f9b88000000b003b87d0db0d9sf3642325vke.15
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 14:51:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670799076; cv=pass;
        d=google.com; s=arc-20160816;
        b=lxm2dKc++u2VD9KnrjAsKR3+/9NowgH5WqAIUHHg530ZJH/Th4H//oA0YLWS5lSeeq
         Tmw6DocT5Mumtc1Bxy9vLr8sKmECw/CBmsZrQGp7EE055REnrQ6Cwy91vMBPTKsx1Hh1
         zSBjrFLSWsWhZiT09Y7EOlQDRc7QSVDz6V5HZHcveZDmzr6HdWR28icnVPvNTDrvltHy
         dV3QEy2EcVLtIJY6EUJ+2r1lQ4+6hQcnRODdvAx9zh5B/yBdSzG2T9fKUI9iOt4rC4/R
         wJ6810uviAsAdO4PVZPfbySlvP/7PwI3J/3Hr2wAPHmuyI6MT98bbe4OQcvr0sci2IL4
         antw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+IGT8dT+BDrUnbi3YQday9pSIUqiFpy8Q/XqgKSyxm4=;
        b=xB0YxhHgcEqcT9Oz1aYQt159+ElrkB2uH6l5pkHcQVtiCbhrWeFmRcEP3vUb3ToAIH
         O++JwjsY56fJoilor0f/VxY26lZi5+r1D2FjzQqStNVDkwDkQu5Vwd3HQgi8ZsFKBYyD
         xyJqAZN/0nKvS9u1KfxUCUjScKTLBo2rupeoxWaZbpVR/zVzNP74Fiv8JXp8e5Dub5Ma
         R5ius4J60ftJZz2r0RnSdZSHZKpqEbT5iA9PwJuZbo6ctVOYwmPcbfqGJN1/2FMzDk+C
         OOrBo+BVRYlOD+7fq2wBQaEUA4bW9AmFlCvJvN2pd4LVDM8tsuJN7ilR/sdz+Fab2R/K
         Sc+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ACD0EiTE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+IGT8dT+BDrUnbi3YQday9pSIUqiFpy8Q/XqgKSyxm4=;
        b=J0ipZmuFyMQ4PSm3QrK4iHJO+2sbmFHLxaOqoamMudoh2/mOMX54svpbQRNWZecwvC
         e/TO9roTbNouE86oGWnAuym5X7+ynIuL+fFD43T7tXtH7AH5kKyMBDwshDYY5xG2PxwZ
         fKGVXu12PREVw0xzTfqzGbby+RGGcNDXu91RB4LrcrI7i8QmATvSrEJKDkccfCJn9OnS
         P+0zEsjZgNorgTxKx9U11VAnuQFCYJkS/3aWY1gAFCqC8n6GJiMDt57Zy6eo4RJoR+vN
         JCsCApkGLefs6uLrqMKiAzXYylkRLLMfh7xIWleUKn9f2297Y87aKeTykPBQr07gPm0S
         O+wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+IGT8dT+BDrUnbi3YQday9pSIUqiFpy8Q/XqgKSyxm4=;
        b=RB+mxdJbkVd/7Cx3aeN2Ocmr6J6ii9fIUGgw8FcSk3qeoXB3qn5R3SiLCN9FSs7Mn1
         UBUxnembN+0O/zYlwwq9F90lk1MU53FDqA0cIZPrDRSLnD3OpyC/X4N1zOQEmr68EwyH
         FnPngvhfUo3DTwIyD1yrcuZI0V8NaZQTvbr7lQAGlJqkywYKkuHvpRgurWkRAHHvvYAT
         yU/PRWt/M7LPXnPFXKuCjf7DgAPcMbL2mgM9G7ZjOOgow/FPWcbyNAT3ly8fn+nyaTA1
         +2PGTJY59Jp+vufBbcZnaVQBFbJ9Y2cx/ahjOtxblw38FmFUhygVCYnZ0ON4+phgqzr5
         vSEw==
X-Gm-Message-State: ANoB5pkeJsg7VPVPeHmidV25s6BUuLcpaBKiZ/FXaIsC2TaqBav/MlJa
	o6Cekxi/17+IvEQDdo8wvV8=
X-Google-Smtp-Source: AA0mqf5Jzk/Gm5YNg0ZOm+aC/HCWf8X9GXgLZwBL1HCJdYTcxcq7WMALNP8dBuwSHhfm9lTvoWPWVg==
X-Received: by 2002:a67:f2c4:0:b0:3b0:f932:5a40 with SMTP id a4-20020a67f2c4000000b003b0f9325a40mr17697162vsn.30.1670799076634;
        Sun, 11 Dec 2022 14:51:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1cd1:0:b0:3aa:ea29:71a5 with SMTP id c200-20020a1f1cd1000000b003aaea2971a5ls1807359vkc.8.-pod-prod-gmail;
 Sun, 11 Dec 2022 14:51:15 -0800 (PST)
X-Received: by 2002:a1f:a9c6:0:b0:3bc:cf73:98cd with SMTP id s189-20020a1fa9c6000000b003bccf7398cdmr7966195vke.16.1670799075852;
        Sun, 11 Dec 2022 14:51:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670799075; cv=none;
        d=google.com; s=arc-20160816;
        b=bnyyeWSdiROGUw9+EaGLo2kucWv1IADDzcdyFLED8A41j17rtaRUd93OtvG+/a6sR0
         utHheTHJ3n4/+ADphDuZ/HixfYzMgzskuZ898J7DYjr/7/5cCLHHmIQ2LzcLCXzZ07dR
         9ZqLwaS+LNzv3usyevM+3EnGsUlMfbIbmm+PNdHkq4DuDDXKlA3WkBp0v8shfWF7vIw5
         hD+9SFLueRGkUGHjDB+Y32Wsk4NX9LtvvLijHxGmaW7T/OLqIpUqsbCxFQWcol6ZI7MM
         yP3Mtv7IlpaYA9/oa40OQJHRJ5hpCdvvpak3v8pkfdMblFgB4eMNtAYwb0jO/3Ei20Ul
         yGrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ku9FczodgVi7IuURoZl4bCpnlwjQxOtO2oc27QuDGyE=;
        b=g/DMaY0Pk4oFGUBSBBhSTYq7eiTNvGpjkE25VvgxgTXciZJagNf6dGggIzCmsNwQ+j
         Dz50WR+Hl7dm7ul4XE8MtWPh56wvSYibAC4u0Q8AVjypmpH4l8QB6xXYR3g6VP8FKEqV
         w8fy8UoDZYOlZuOtjt8wTiWrwrIB3w3AQ2GbkbHY9n6ta5lzWNStVn+JPFiE3EvjPxoK
         P9ZDRQWhKGdUJoJgtiaCwKctviNvzoVYWs6KJNd7xob0fMgVGRx8UVMqU2O7yXD4cLJe
         A3ScQHrroIxsSX3X1WpEb78D4+p+kYCAj0BzBo3me+Sf4ttajm6R1zbibjQdfb1vv6FZ
         ooKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ACD0EiTE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id e145-20020a1f1e97000000b003b803083c23si511797vke.0.2022.12.11.14.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 11 Dec 2022 14:51:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id o127so11674329yba.5
        for <kasan-dev@googlegroups.com>; Sun, 11 Dec 2022 14:51:15 -0800 (PST)
X-Received: by 2002:a25:2b41:0:b0:70b:87d5:4a73 with SMTP id
 r62-20020a252b41000000b0070b87d54a73mr4987665ybr.584.1670799075296; Sun, 11
 Dec 2022 14:51:15 -0800 (PST)
MIME-Version: 1.0
References: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com> <Y5ZM3HCnTcLvP2vy@itl-email>
In-Reply-To: <Y5ZM3HCnTcLvP2vy@itl-email>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 11 Dec 2022 23:50:39 +0100
Message-ID: <CANpmjNPZwtmMvAOk7rn9U=sWTre7+o93yB_0idkVCvJky6mptA@mail.gmail.com>
Subject: Re: kfence_protect_page() writing L1TF vulnerable PTE
To: Demi Marie Obenour <demi@invisiblethingslab.com>
Cc: Juergen Gross <jgross@suse.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"xen-devel@lists.xenproject.org" <xen-devel@lists.xenproject.org>, 
	=?UTF-8?Q?Marek_Marczykowski=2DG=C3=B3recki?= <marmarek@invisiblethingslab.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ACD0EiTE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 11 Dec 2022 at 22:34, Demi Marie Obenour
<demi@invisiblethingslab.com> wrote:
> On Sun, Dec 11, 2022 at 01:15:06PM +0100, Juergen Gross wrote:
> > During tests with QubesOS a problem was found which seemed to be related
> > to kfence_protect_page() writing a L1TF vulnerable page table entry [1].
> >
> > Looking into the function I'm seeing:
> >
> >       set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> >
> > I don't think this can be correct, as keeping the PFN unmodified and
> > just removing the _PAGE_PRESENT bit is wrong regarding L1TF.
> >
> > There should be at least the highest PFN bit set in order to be L1TF
> > safe.

Could you elaborate what we want to be safe from?

KFENCE is only for kernel memory, i.e. slab allocations. The
page-protection mechanism is used to detect memory safety bugs in the
Linux kernel. The page protection does not prevent or mitigate any
such bugs because KFENCE only samples sl[au]b allocations. Normal slab
allocations never change the page protection bits; KFENCE merely uses
them to receive a page fault, upon which we determine either a
use-after-free or out-of-bounds access. After a bug is detected,
KFENCE unprotects the page so that the kernel can proceed "as normal"
given that's the state of things if it had been a normal sl[au]b
allocation.

https://docs.kernel.org/dev-tools/kfence.html

From [1] I see: "If an instruction accesses a virtual address for
which the relevant page table entry (PTE) has the Present bit cleared
or other reserved bits set, then speculative execution ignores the
invalid PTE and loads the referenced data if it is present in the
Level 1 Data Cache, as if the page referenced by the address bits in
the PTE was still present and accessible."

[1] https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html

This is perfectly fine in the context of KFENCE, as stated above, the
page protection is merely used to detect out-of-bounds and
use-after-free bugs of sampled slab allocations. KFENCE does not
mitigate nor prevent such bugs, because it samples allocations, i.e.
most allocations are still serviced by sl[au]b.

How can we teach whatever is complaining about L1TF on that KFENCE PTE
modification that KFENCE does not use page protection to stop anyone
from accessing that memory?

> >
> > Juergen
> >
> > [1]: https://github.com/QubesOS/qubes-issues/issues/7935
>
> Does that mean that Linux with kfence enabled is vulnerable to L1TF?  Or
> are these pages ones that are not in any userspace page tables?  If the
> former, then this is a security vulnerability in Linux and must be
> fixed.  If the latter, then the two options I can think of are to revert
> whatever change caused kfence to produce L1TF-vulnerable PTEs, or to
> disable kfence when running paravirtualized under Xen.

See above - it's for kernel memory only, and the page protection is
only to detect bugs of _sampled_ slab allocations.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZwtmMvAOk7rn9U%3DsWTre7%2Bo93yB_0idkVCvJky6mptA%40mail.gmail.com.
