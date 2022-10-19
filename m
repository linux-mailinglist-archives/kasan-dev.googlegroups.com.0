Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUHIYCNAMGQEHP5XB3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60072604EA2
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 19:30:58 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id w13-20020a05620a424d00b006e833c4fb0dsf15222568qko.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 10:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666200657; cv=pass;
        d=google.com; s=arc-20160816;
        b=lHxav35aIHFKJd285sXAMawYN+1obq9N0GGqOp6N63hxU9fYlVKtj0SPFvqhEmMlJ5
         2ivYE+ryPuN0EIwZ6F95/cn0yxUv0bJSSeh4N6WAir/+LmvjSkHb5c1mNGe+qT0YgFts
         f8NK3Cwp0WiguJjKcRPkHWkWHs7NueUi5UHrqHBMvDhTQZdFiXMX8mjJUpefdd7krt6k
         qyssY1dCpbWufxU42yvfNQNJKLlxF2x2qvqhZQTFwsx6PIKRAvlmDr/ah0UYKanyePfi
         f/R0h4RL6YH922K+27CROhJ8Pv6dzGB7pCZ5x7GQ3IBuq8wHwCSXZLUy57Kla8l25Gsd
         QRlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TfCBfjktpcXP9szOnyzx+UAtDL4qciA01qukcyfJC+c=;
        b=vOYLcjgG17BGA+B5PPrtsIpgET317wBiP78mwkYUal+PAJS54zZPlr2e/NcxnhdYxY
         i8zymEwX07L3zOd8iUCWOSn49UybzPSE0irT6xkw9q7G9nCdbJytrsxL76CbbVe2tCJq
         goFsTglaibnRHwulIrQfn4KBKazjTW/zHyIIOyjpg0tbsJIroL9Lg1YQdpXQV1hzdc3D
         xQE3hX9EY/4MHgaADtyBVBE0LEXJJqoA4vX9f9fx1t4YS6vqcwQ8smQ4CG9UxLGUaHoG
         +PbSPBa2NNZD8yFL9wVbX/ZufMwtZMvRb5X2XKwlnAtNpH1a/Upg911PxwbLpfiMuuLO
         KuUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PLA2JsXS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TfCBfjktpcXP9szOnyzx+UAtDL4qciA01qukcyfJC+c=;
        b=kLZ1mn6b823QY9/zg97/NNGgF78skLpmNxl/bL6vaWBmFQqgfU1xeh/n1p7MaW1Fzp
         wLm4FjtfhEUhCbSIjn1qema65rMDleHy888EY1TBz6orOL15wrmWMSQrPhrv7z2JZgB8
         WyYeWC5vAx6J3L4M7ENAjnlXwJNlZcQ+hxTiynsqCMt/Fw79SgZ0x0rn+6UEi9oCV+76
         8EKurbiV3rz8QoSP/4L+03BikVNpyJdXYOmV5nW635ZAuL4SHkY/i4qmUmxkYszsFaBN
         EjKrBw/mCde1elyE7tomahg1kocC+XJ/sESl8nBRLE5kWYFVBEZ8uqmbg7lEKDUAJU1j
         RGvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TfCBfjktpcXP9szOnyzx+UAtDL4qciA01qukcyfJC+c=;
        b=tAs6kh54q4mA+CPC5AfFXr9qN/RTYMIXQ9zgIAd32wvey8en5683H6R7M8JrJELuTc
         USmaZNp3mawiIsHu+09dp+LPk9b5KNbNPxUHLKF8FjiC+3hVOzhcqV15aCt8E6Cnf7v5
         JGIJVPurVJsmB+HRrVR6Peb5IIddXsdYSckL8qxazMdLEJnJgE+JVWNQOptarHTE5dPh
         cdpoJ4jHY8ynByvkthFzlirYRsw3cw4+tZ0LelwDr3AdZAqZBw1T5eXweP9Udq4E5rcL
         c9P9+G6mLTAK8qb+AzVQRRG2KL6WGhsRHwjwADDm+BKE/2HIIw1lwKgMQvTyhtLvCewD
         djGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3TGmY5rST5H+XkdI6eXVj+MBbNpIucEN/Wj6yjAS2L7K2gcph5
	1UYlC1IfkQaHHND9ZZWcJGw=
X-Google-Smtp-Source: AMsMyM67qmq0GStOQxNt6fieH4cEyFIlBc8daw87R+GSWFOP+ZS4BA+ZUGCPqGoPTko+J+3+hwU6SQ==
X-Received: by 2002:a05:622a:184:b0:39c:ca1f:cd65 with SMTP id s4-20020a05622a018400b0039cca1fcd65mr7552529qtw.565.1666200657184;
        Wed, 19 Oct 2022 10:30:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:410f:b0:31f:22fc:d794 with SMTP id
 cc15-20020a05622a410f00b0031f22fcd794ls12067915qtb.7.-pod-prod-gmail; Wed, 19
 Oct 2022 10:30:56 -0700 (PDT)
X-Received: by 2002:ac8:5c56:0:b0:39c:f4dd:8c4a with SMTP id j22-20020ac85c56000000b0039cf4dd8c4amr7330229qtj.57.1666200656566;
        Wed, 19 Oct 2022 10:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666200656; cv=none;
        d=google.com; s=arc-20160816;
        b=qNNZvpjc2B+c2BJJL7Y27+TAfj++NwVQy1sA4axJvoVYk+a3RSyyYC7Vm7maO5GwTJ
         7Luj1R/hQpCCTu4HHHrAHZ9BD6nxTeY8/VExgbHSMu5ZyVTEpm1rQ6mn4zn1wqdiBYvh
         ZqGX7DxOwcDTmJrAPaPsLD+yO5qUmch0fyZQOQsyFwKjXa1Y1hK2KR/OLjjtd9p4XJ8U
         wk9HYjFitWm0V3SRuqyNRAroqhX10dSgX6gJA0nG8KiK9CvHYUiYkXWVZdZ1CBDWPduy
         Hm5my99gyD3p8a+gvL7jui14jc9wTFNJSvnBDlnuYMofgROSVi4/9GZxRUn98xswcUN/
         H88A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BFRWd7vrrVi87eI0lxP0gM69HCWszoFdIqs2so5GqDM=;
        b=HbYNsTbPNiwDyWECX0Lbh8NG0ZarEw0wdoMp5/Z4KBH9gfbbxJ1N/P85OXBgGnP2v0
         0Zqt5vCuOEANn9oRTVd/F2euxoOawUNsF22jczA/D6BtA2I9YAClZHJtT9733T57mMzv
         jaB5wXAYLkuHYL1YknyVnI0FjOerp1ItDZavxJKpYEzXHwKaNYqcaX3z8Otd1UQqgEXo
         PXNyDdwn3ib/IuOKGZdts3mWF3cuzr9LDid2YMCX07gjaoBmKGRo7ZMBbZtOwOdqWv6J
         +yGCWPR3UZ5mYCkVkjJ8eE3riH3SHAV4XvT+WeNY58LQ4Jw/5+VQ6jkdY1qjbGqwlgUw
         CLnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PLA2JsXS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id a28-20020ac844bc000000b0031ecf06e367si807356qto.1.2022.10.19.10.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 10:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 128so16879670pga.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 10:30:56 -0700 (PDT)
X-Received: by 2002:a63:4a41:0:b0:452:bab5:156a with SMTP id j1-20020a634a41000000b00452bab5156amr8132651pgl.486.1666200655754;
        Wed, 19 Oct 2022 10:30:55 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c3-20020a170902d48300b00178b6ccc8a0sm11073833plg.51.2022.10.19.10.30.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Oct 2022 10:30:55 -0700 (PDT)
Date: Wed, 19 Oct 2022 10:30:54 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Potapenko <glider@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: -Wmacro-redefined in include/linux/fortify-string.h
Message-ID: <202210191030.EC5C138E@keescook>
References: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
 <CAG_fn=WYnfNHC3S1S=mCTKTnzL=UuH7Oz4W3HjsTXEQUtjrxtw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=WYnfNHC3S1S=mCTKTnzL=UuH7Oz4W3HjsTXEQUtjrxtw@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=PLA2JsXS;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Oct 19, 2022 at 09:48:27AM -0700, Alexander Potapenko wrote:
> On Wed, Oct 19, 2022 at 8:37 AM Nathan Chancellor <nathan@kernel.org> wrote:
> >
> > Hi all,
> >
> > I am seeing the following set of warnings when building an x86_64
> > configuration that has CONFIG_FORTIFY_SOURCE=y and CONFIG_KMSAN=y:
> 
> I was also looking into this issue recently, because people start
> running into it: https://github.com/google/kmsan/issues/89
> 
> I have a solution that redefines __underlying_memXXX to __msan_memXXX
> under __SANITIZE_MEMORY__ in fortify-string.h and skips `#define
> memXXX __msan_memXXX` in string_64.h, making KMSAN kinda work with
> FORTIFY_SOURCE.

Oh good!

> Dunno if that's necessary though: KMSAN is a debugging tool anyway,
> and supporting it in fortify-string.h sounds excessive.

I'd much prefer letting them still work together.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210191030.EC5C138E%40keescook.
