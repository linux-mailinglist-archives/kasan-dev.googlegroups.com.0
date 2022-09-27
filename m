Return-Path: <kasan-dev+bncBCLI747UVAFRBLPIZKMQMGQEBCRSN5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A8D715EBD3A
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:28:31 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id l2-20020a170902f68200b00177ee7e673esf5941396plg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 01:28:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664267310; cv=pass;
        d=google.com; s=arc-20160816;
        b=yGh80oh7mnT6ImySsHiD5ZOmFQ4AF06ArHx3TUj1VVBRsolAd27FEWAuF+d01j96oV
         fvNKczq1DyqhB8S215yry2VBMRjE8rL0rxjOxufG+4Tfnu8Jh9XpzgyFBD0M/XYnbnIv
         Syvtuht7xueBoe48g5KfsGCkpq51zdRvALD0wLZutt1zHbp16Aw7ql1ksvoTQf2IiB7X
         G4ZiPNC1rsiDwqQqGdTj1GKQKkbdQinX4XFXGjVy1aGsWjOCntfg0W8MP43r5XGWk0aL
         kFlFDNLNhTxPP7g9b9U/5NTHiTe3gYtOaYhrFJq/ikpK5T3pC/3CEvzvWcItXfjqrZBR
         I/kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=onODW0gShxB8mlLJJrqeTSKQFgqR6DZYmkYEFJeE+G4=;
        b=SKm2o41xeWNmTykdb00k868GpAslyAEGPzcZqg4GNoSrepINtvsNkjFxo1VKFjV58Q
         V2lzVQ+kS14QoqYX3gZs8sqFe+3rcFoiVtOMOYh1cUEJSqRPvWzxqmcnKNXEe6JBhH0l
         LKLnBjJVJuK98kvK0/UzeXM5JgFOhpCkHbywLxf2nY8BL6syKBYCdxyBXS9ESOTY681R
         A/UU9YumXEbXyrwJowGLkiSrNqSAtxMsmVwVoxQG1YIG9mpf7tiBNG5Qd3YY4+e1S5sS
         KRHEsPIJWJmx1q5Q4XWqqltQUmZ2VHs1NnM17Ah616AcBb4XfbfaFIJCqRHihY25HoLv
         8hdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Q4YS52KU;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=onODW0gShxB8mlLJJrqeTSKQFgqR6DZYmkYEFJeE+G4=;
        b=JumNw21wsOuZ5WHbw0jPb9dT3V91LcGenvVzgbUusG4+KsxPurRhsNZ90wNb9cm4Aa
         Y0BhXb60SeHzQa8oqnTPGdVYW3+sNlb1bY5ZnSrxz4T+uNZZcuPmmSNBe54Mkjd2mEXh
         CW0Hw5TkjS5ZCK1wQ2mtWk0rnJCiOZm6HFzfpn4QWZEGdjSQD8bnl8Q9hLnqFd6zy9ij
         qUixigXxgzVUfaX1dOsD3LQOzsCzeWW3rDqxWmODETQUr4uibiTVHpbcDV3YDZXrCsei
         L2WEf1oDdEb7jScOgvokS1joaMOm2jKRmCkD4z27pdaY4Ze7BwBxEN5N0bbqV4rPRgfq
         BNVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=onODW0gShxB8mlLJJrqeTSKQFgqR6DZYmkYEFJeE+G4=;
        b=xuu9ybVpJaijc98gyGQjozYQFMw9DNiqPI1OwFz8oP6UEe39fzueSt7BcSZz2xD/9F
         UEsFaJw6f9JYrMtBRzizR4qQZ+hC8qIOWa+HnhrzPBlAhXCYYVKNPsJ85oHzSZKSFHYq
         syc6IjovC7aQbPoV2QrcPw7l3tJG3KtBT5hyXgWTKhIul2aPXoOkz/MDbWErM0t0It04
         tKUxJsbqT5+R9cJFcT38aEyhcscV0/+3c1B8YNriQIbS/BvIqxpBuMN7ZBXYNaXNwFql
         GNWgyPq7Dy7o3Qo8bo6A71mPHPt+B+YQm/+qw7fbv8qLxkiOvjMQXT3ChsRHJxSrg89W
         Kbvg==
X-Gm-Message-State: ACrzQf24n1bFt9mHYH6OdCLT66sarWdwNhGVycr6mTnPSSrhTOntXrnu
	SsX9uovk4DONSy1AkB+coF8=
X-Google-Smtp-Source: AMsMyM4cj7mIt9TCMXX0zSbJlFMAqAsydpU5HSb1NzfmBrgghFjHKY02TzQ00iX324Z90VGhi7NZsQ==
X-Received: by 2002:a17:90a:e60c:b0:202:6ef8:4b52 with SMTP id j12-20020a17090ae60c00b002026ef84b52mr3325053pjy.236.1664267309985;
        Tue, 27 Sep 2022 01:28:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:290a:b0:1fb:474:3810 with SMTP id
 g10-20020a17090a290a00b001fb04743810ls340766pjd.0.-pod-preprod-gmail; Tue, 27
 Sep 2022 01:28:29 -0700 (PDT)
X-Received: by 2002:a17:90b:1d08:b0:200:823f:9745 with SMTP id on8-20020a17090b1d0800b00200823f9745mr3216948pjb.84.1664267309259;
        Tue, 27 Sep 2022 01:28:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664267309; cv=none;
        d=google.com; s=arc-20160816;
        b=av8sWGPkaFW8wZV2phDbh76Jfq6UYzudyX8a90oG+aid+0yufZb6kzNa9XMj8LsC6y
         zi1A1p3/gY0e3AR4Os2tdwMDDAmeW64fIR67ae6HUefrQvskOOF8XnAjjT7YfXXjeXiD
         QJl6IvuYArXFBR3oPXxbAFKN+QHERg0LcC0DQVQnkcQywAGvPZXM5SwhnhFgqURvMJWZ
         2cVFkxjqFJ2QCUvLS7xZnrupmczNnIz/qQvL9vhjQbfOhr1T9fanZcrmxLPOuY09pHL+
         1I+i1OQfihKKPFxJu0Oxakq8ObajxNupi6/qbmSymloMuIBOHgZgOgSChT09qVMBi5OE
         3Tvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gF2B0EX39catiZugICdowKOfDfyx3TjUROolfQVqhqI=;
        b=jBX8XIfC+thMj9Df40y/GOaS5xgxwGK4dzy+PlCPvMkssXNp6VX9O8Hm3ERN20wpaI
         6+rHZwBfIw9uU76e0bM1IJiuPP3FFngc6BqWoCYWpMAc5JjsLjxZgIE3a+cAmWtxi/iz
         +sgaRlY49VZizL7fkHyFXm6bf2quPXgAg1alNVzvF1czapFlHJ/nK7XlzabKokSNdEw1
         MlCNeNpNBwyGL4DiO+sjPwuZN2xdZ/0v5XPgbmQtsb2YgpOZb2IK9Ohj2Yq7qoMQ6LWc
         XGxACGQVg5CIm+mEKXUyIuggw8fXGb61eowRCnLKHlAOsrhMZW8GYQi51hYfPkWWpTbt
         lQNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Q4YS52KU;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k1-20020a637b41000000b004350f53ef49si33184pgn.0.2022.09.27.01.28.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Sep 2022 01:28:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B109F616FF
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:28:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D7447C43470
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:28:27 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id c6465ece (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Tue, 27 Sep 2022 08:28:23 +0000 (UTC)
Received: by mail-vs1-f49.google.com with SMTP id m65so8981795vsc.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 01:28:23 -0700 (PDT)
X-Received: by 2002:a67:c289:0:b0:398:cdc:c3ef with SMTP id
 k9-20020a67c289000000b003980cdcc3efmr11024734vsj.76.1664267302601; Tue, 27
 Sep 2022 01:28:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220926213130.1508261-1-Jason@zx2c4.com> <YzKZnkwCi0UwY/4Q@owl.dominikbrodowski.net>
In-Reply-To: <YzKZnkwCi0UwY/4Q@owl.dominikbrodowski.net>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Sep 2022 10:28:11 +0200
X-Gmail-Original-Message-ID: <CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg@mail.gmail.com>
Message-ID: <CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] random: split initialization into early step and
 later step
To: linux@dominikbrodowski.net
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>, 
	Andrew Morton <akpm@linux-foundation.org>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=Q4YS52KU;       spf=pass
 (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Tue, Sep 27, 2022 at 8:35 AM Dominik Brodowski
<linux@dominikbrodowski.net> wrote:
> >  #if defined(LATENT_ENTROPY_PLUGIN)
> >       static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
> > @@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
> >                       i += longs;
> >                       continue;
> >               }
> > -             entropy[0] = random_get_entropy();
> > -             _mix_pool_bytes(entropy, sizeof(*entropy));
> >               arch_bits -= sizeof(*entropy) * 8;
> >               ++i;
> >       }
>
>
> Previously, random_get_entropy() was mixed into the pool ARRAY_SIZE(entropy)
> times.
>
> > +/*
> > + * This is called a little bit after the prior function, and now there is
> > + * access to timestamps counters. Interrupts are not yet enabled.
> > + */
> > +void __init random_init(void)
> > +{
> > +     unsigned long entropy = random_get_entropy();
> > +     ktime_t now = ktime_get_real();
> > +
> > +     _mix_pool_bytes(utsname(), sizeof(*(utsname())));
>
> But now, it's only mixed into the pool once. Is this change on purpose?

Yea, it is. I don't think it's really doing much of use. Before we did
it because it was convenient -- because we simply could. But in
reality mostly what we care about is capturing when it gets to that
point in the execution. For jitter, the actual jitter function
(try_to_generate_entropy()) is better here.

However, before feeling too sad about it, remember that
extract_entropy() is still filling a block with rdtsc when rdrand
fails, the same way as this function was. So it's still in there
anyway.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg%40mail.gmail.com.
