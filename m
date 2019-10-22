Return-Path: <kasan-dev+bncBCMIZB7QWENRBCOSXHWQKGQE5SACDTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 830D9DFBA5
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 04:27:22 +0200 (CEST)
Received: by mail-yw1-xc3b.google.com with SMTP id r64sf12063101ywb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 19:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571711241; cv=pass;
        d=google.com; s=arc-20160816;
        b=Js7id/ZNE5ZhA9/s2lZG5Vqjx4uzQepfs2WQcZqqQoz/sXU4RtLkt9Ad46cPDILo2Y
         mkAhesu7chUW1zun5aMNavbv1I+rs06f3tw95dThDa1R/GZ7ogYcwd9DYpqmhTcXbCqR
         wJz+X8kUYxtXuaSH3iCKcYCKZ7M1/weG5z4gWOIme13KSCB0sSz1+oCVt3h52U1EvzeQ
         EHFtPbXOvor4GQV5HugQkY8dT2s8GRtFGGcDSgeHYYVibL2vY8Pj8UloVRP8kdPyxeDg
         2PypwTlW6UufQf3DzocIxsZDFxHk/bFFP7uYWhUynTjTVWJMK0C6ggxfr9r1UaxktY4g
         cBPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UPdgh6r/9P8QXbiOKfvCspH/xshktm8IF0CszXO7bHU=;
        b=0qrr9kuLSGI1NZ3L8W8a7TNKRPf6/WoqE5wtDy2kQUh0bQxHI2rCYzuSEPIIQe6Pn+
         Lba4PerlL3GrmmClAsbm3o2vDPZA8YZq8si4RuTF4fbRcu5n/eiBOv97OkgZtn0/bpSr
         +Lo+Q3cdkpyaEOmife3x6EpClvI1aBKhX7xhbKDnAylZ4Y52FfUzzu8aESorRx/YEUWE
         9XwdxqNK4VTQYFqgb10y5GkVjgKsgxLiZW3iYZ02rdrUfUmaIVG7uVBKE0wkQJ9JyUpt
         1ukhO2UhsxGaXXNogjJYaLEdnkXS2wNxxZsJW90SW52+CLnyLonICmvM2fRypO8x9IzV
         uH7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gUPc3+r0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPdgh6r/9P8QXbiOKfvCspH/xshktm8IF0CszXO7bHU=;
        b=hPHpxguPQCry0f/nkAOd67Qx1LVaNyyCFRM7g332KFAKSzftj0rywM3HB0VTSHa34Y
         d8jBTr9yTMPM1VU4OTWIsM6OIZZ/39Hf9z9LDpjottjQiJhkW+dFkItw/ihQN6ROvOtA
         SJoI5Yb8t4fTOffwZHXPuxDZwaFYgZVxTzha7VCmDyJurqmvt35CodZUqVu/kmhZOC2f
         v9dKgKw0IJe4g3B7qzvh7GZV7Gtm53oEtGY+QgwoJhOla0/eCDjNMrc/PztEEM0/TZQO
         1GgDWw4gBB4qdoBqeZvB9do9mSjDdsS5JbOucH83dS4Ck/HlYvz4Xaz4Lwp5UJ3jDpTp
         TZlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPdgh6r/9P8QXbiOKfvCspH/xshktm8IF0CszXO7bHU=;
        b=dhyV3acd2q2WLeSAvJtT3sUUjD6JSVGgPtpHWB4O590HWsc2dPaoPE8PR9FnpNgu6K
         z7ukpIBtkHBcKlYvMtMBgMXd3WNi2KYcjQ50dyHfXGFsqKfMpxkF0S+M/RyNpt0QqgBl
         u7wFxpQF2NGM7ioUzT2txvsBFTTv//N/a5Zc3sOMrfj28PgqQ9KRKvWcjJ4DwoQjDYuA
         uj9i8k8xlTDJoyOuX46FevVMDrVKx+8e/Y+RFMRikSHD2Z2WEugdAK+igk+mv209Amnv
         OQK93hF9OWtITdDaOGR4O25XZgslLVmgS0cPs5NDpD8ZSpyEHIYDnlDwnyzkb8Z6AxbR
         PjkA==
X-Gm-Message-State: APjAAAXuqhowUPk9Jgq0dWUTp0NOIOnr4dTY+y4uTjUSv7tn61cQbQO/
	NAPeWWLQM9ODGHtkBseKVL4=
X-Google-Smtp-Source: APXvYqwxt+kovfXacAP9ArWkjsLbUHns+79imkJg6Ptm31vf/12lWBBPkmRBZkbQCYWACnA/krLugA==
X-Received: by 2002:a5b:384:: with SMTP id k4mr833132ybp.61.1571711241464;
        Mon, 21 Oct 2019 19:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:3b81:: with SMTP id i123ls1029280ywa.8.gmail; Mon, 21
 Oct 2019 19:27:21 -0700 (PDT)
X-Received: by 2002:a0d:dd08:: with SMTP id g8mr715446ywe.194.1571711241087;
        Mon, 21 Oct 2019 19:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571711241; cv=none;
        d=google.com; s=arc-20160816;
        b=bZXNVLYZEnuoD4TLTzCTqNxMmcEwVXQgdNdrQyvNgEa96/xSmS5yEI72GDncRMD3NY
         78vdKtVZl+FXAsnzOJ8Nc3g36b0xEfwZKbGEauuMqNpGEvA/thd2QNR64Zcuytigh993
         pBNmAoC8j2/AQOFsrdzuNXFhk24J5IHtDdtcj/NEb1GV4rg91Jssfu/Yq8iCgSNDSdbD
         +sLAAhYtCEpWGzODd8JiNeVeRhg5eom5UuF0taV9YHglsUELVRstY8/ChqzXFj3+ghsz
         yvE+BpZl3byTZ5dyl5n/jTwzcG26Z19gQsZZ7ynKowhYbMfvNP91OvVcmkc/n6CD+S6d
         wRtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VN4XOQxWZMWnSTs2Dh2Lw0yjzpEOfDxml7hxLuxIwLs=;
        b=FG3XPp96EgqM2KL6YH/lLp9vVy6SZLk9tywUJbbnWQcQAotbE5W1an1dx502bOc7aJ
         X37qtX9tQpo7YBpuPwHvHEq9Ti5MlZw08WjKIcrflDmAeU89jOrCh6KxvBtYPnlgXZSL
         iEx6n06sJwY7t0g4rGLokLG7Rciw9V4E12nLSy8azxBjmCjC+Vbb5vAANt89DFyLjlI3
         LUIuh5sRAJVTQFblknVNBD9UuLv7dsWJY6YIsOraWqL1qUpVI52vtIDnkq/uWw9DvyEG
         kDSCk2hbbawSiiUaMc0P8VGGzSKPTa2hSRaU5uZQ7pgGcrGQJ2aFOXTMWAtSeWYtt+qg
         9ovA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gUPc3+r0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id t73si1010916ybi.4.2019.10.21.19.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2019 19:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id e66so14824611qkf.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2019 19:27:21 -0700 (PDT)
X-Received: by 2002:a37:4a87:: with SMTP id x129mr908751qka.43.1571711240126;
 Mon, 21 Oct 2019 19:27:20 -0700 (PDT)
MIME-Version: 1.0
References: <20191022021810.3216-1-lyude@redhat.com>
In-Reply-To: <20191022021810.3216-1-lyude@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2019 04:27:08 +0200
Message-ID: <CACT4Y+YQf-aje4jqSMop24af_GO8G_oPMfrJ9B7oo5_EudwHow@mail.gmail.com>
Subject: Re: [RFC] kasan: include the hashed pointer for an object's location
To: Lyude Paul <lyude@redhat.com>
Cc: Linux-MM <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Sean Paul <sean@poorly.run>, Daniel Vetter <daniel.vetter@ffwll.ch>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gUPc3+r0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Oct 22, 2019 at 4:19 AM Lyude Paul <lyude@redhat.com> wrote:
>
> The vast majority of the kernel that needs to print out pointers as a
> way to keep track of a specific object in the kernel for debugging
> purposes does so using hashed pointers, since these are "good enough".
> Ironically, the one place we don't do this is within kasan. While
> simply printing a hashed version of where an out of bounds memory access
> occurred isn't too useful, printing out the hashed address of the object
> in question usually is since that's the format most of the kernel is
> likely to be using in debugging output.
>
> Of course this isn't perfect though-having the object's originating
> address doesn't help users at all that need to do things like printing
> the address of a struct which is embedded within another struct, but
> it's certainly better then not printing any hashed addresses. And users
> which need to handle less trivial cases like that can simply fall back
> to careful usage of %px.
>
> Signed-off-by: Lyude Paul <lyude@redhat.com>
> Cc: Sean Paul <sean@poorly.run>
> Cc: Daniel Vetter <daniel.vetter@ffwll.ch>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> ---
>  mm/kasan/report.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 621782100eaa..0a5663fee1f7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -128,8 +128,9 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>         int rel_bytes;
>
>         pr_err("The buggy address belongs to the object at %px\n"
> -              " which belongs to the cache %s of size %d\n",
> -               object, cache->name, cache->object_size);
> +              " (aka %p) which belongs to the cache\n"
> +              " %s of size %d\n",
> +              object, object, cache->name, cache->object_size);

Hi Lyude,

This only prints hashed address for heap objects, but
print_address_description() has 4 different code paths for different
types of addresses (heap, global, stack, page). Plus there is a case
for address without shadow.
Should we print the hashed address at least for all cases in
print_address_description()?


>         if (!addr)
>                 return;
> --
> 2.21.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYQf-aje4jqSMop24af_GO8G_oPMfrJ9B7oo5_EudwHow%40mail.gmail.com.
