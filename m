Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMSS24AMGQESIE2T3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AA1E9957B6
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 21:35:12 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6cb2ffc83f1sf70200686d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 12:35:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728416090; cv=pass;
        d=google.com; s=arc-20240605;
        b=DprewDX1AwW3JradZp+X6dsAMwiWhEKkYDkInRWpsESnfGLsaXmPl9C1U2sw++3cPZ
         STmo466IdfoWsCoD5c/beuBHLLAt23El7eUOdyAiNpjhPS5JN3V1Zpjkxc1lB7+ayUGK
         46wFoe6fAnndKbObV8Cdl4HAqnJJ6Lhq6u+qR46zFQ+7ms4ov2TqSznfcEsqXc1nxeHw
         I7sNzyT1e4pB0i7VXi/rsDfY7SVAAn/mUJsSPPeVZVVVGPLkBBVxI7QxW0y5a8VbR/BT
         6Jg6uyJIbjkTBm7NnxVviMPQZllb4KsvTYZHClSNATIde4WwsbpFGSMYDiFfNbUfq2bj
         0g6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=p1e+n0TV6BuqpV4LrNdiy5VFzLEKuVBqKp9ycg2VubM=;
        fh=7JOyjB7YJTe7fOY9lr3xJVsUQ444WAV4W04Ge+gE7tE=;
        b=AepmB8w7DNAA1bnX/b+Bq+KVjab+YRIBj/Va+GlRO827T3RksCWHAd0w10vW/RTYHa
         AGguqXBTYrZO/isKXdXQ5vaE2Ax8ODDYc+T2qWjzmkdB/78JeOF2Xz1nI7bZg+rWENPt
         VUXAZIeHrk1Ra8c53z2ymU1hxJyxnTS6MIFOrt7PDSZVi5HSbnwRQQc5mlFrPx70xRAi
         fNPt6qjYMxn8om7n2kR5SrYymajg6zwpanklpJN/lft7aUA0woJA0uS3+iq2XvI/8myW
         PQ2Umo3jXpRb5qK63yvX8Lfuvo/wwnN+4g98Vy+VLtWeH7ji3PI5AMEAqi7knykm6utV
         uNVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mZqZ6N/O";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728416090; x=1729020890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p1e+n0TV6BuqpV4LrNdiy5VFzLEKuVBqKp9ycg2VubM=;
        b=tCgZN09XUdzWHw0nyUcLxjT9jOaFAdt7TcePjDJmNv5wn4p02cOvM2CuBgO4V1HLdd
         EX9ebAn26jEg4N3eqa+F1vQdhGAbfJllkVVooQY8m2OAP1J9f0PEtmrC76j9w572Iqog
         N6YnJ0OHEDOHY1HMfliHA+Cbc4ISEauIuVK+ewzIrRkqQt/jyYYhnLghr/5rKbPhCVX7
         swgVwZG5HAifgcoa6HLK2XApxiqueVNuXQfi5Xc9FV5ctw0Q/KpppvT/DJGDG4WIdADD
         TdW2artHuxl7WDKDsKH6yqHxsDzVd1pyGWjtDBUTh6UDsmPIhbXg/HetuiXC2wd+kghV
         /Uew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728416090; x=1729020890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p1e+n0TV6BuqpV4LrNdiy5VFzLEKuVBqKp9ycg2VubM=;
        b=KHxy+ZBhsfWl7vgQzw+9tYI8kWfuZlnsyR+R0Xt//+0JwCom0TsyC4JQEIrIYSNTQW
         t9DOUp+A7sD14e62BAwn/3LBZh5lvfNoSAnoFOQ90LRSyzVBe3VSdS8EtEWdaR2P/nrx
         LbqHndSLQGOwvfb4QEDHpkDINkd6FVzXWgPNtNcSpatiuDBQAVJaOJ0RETfA0wMzAas6
         JmHPY5F565HrfAzGCSoyLYeBf7d5Z7qWrYH+vArE3hE6cOKTrQsnjeChSR/7UFSSV7/D
         tiAXdaefA3v/CFnYFESw8AsBJnP3bEjIZuASUjdgXJ7AzgM4jqKveeyL3LP1cZc6iDXs
         RUzg==
X-Forwarded-Encrypted: i=2; AJvYcCUuDwPCT8HGnJinqcdVvupLBnJa21hyVRopo9VtYIU1XZqbewngrc1Lc2OOFsdL8EVwdLnqCg==@lfdr.de
X-Gm-Message-State: AOJu0YyLwjSrcgTaeuje3y0fONWtVq26YzloauIBdtVnYxJ1vNa4dfYn
	z0e0NRM6/Q7TWbOOOsYw7zyD7hI0d6HVZMDOLJ2hkJNQrTN3CPnv
X-Google-Smtp-Source: AGHT+IGAOSgEsHPp1m2Xv1R9Efu4aEMsGKo2SkGnI2b/53/HMcVHDTHCAS8MxbOBkuo0UYeipDqdPA==
X-Received: by 2002:a05:6214:568e:b0:6cb:b090:c946 with SMTP id 6a1803df08f44-6cbc95594ddmr1191296d6.31.1728416089529;
        Tue, 08 Oct 2024 12:34:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c0f:b0:6b7:96a6:c5e7 with SMTP id
 6a1803df08f44-6cb8fdfa479ls56880336d6.0.-pod-prod-08-us; Tue, 08 Oct 2024
 12:34:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpN2woszJfO/JT/M9Z/TxOTqdItxlRGphn/hz0lxASSkxDTt1VZbfJmIXS/Uij/7IKMDCaMMrkUUk=@googlegroups.com
X-Received: by 2002:a05:6102:54ac:b0:4a3:a71d:647e with SMTP id ada2fe7eead31-4a448e240abmr136886137.22.1728416088786;
        Tue, 08 Oct 2024 12:34:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728416088; cv=none;
        d=google.com; s=arc-20240605;
        b=bVSiqpyW4TwVaSI4BOf3vhRuLm8evEfeL5OQHcFouIL1FVKPd1JO7JVXvvO4fJBWt8
         k0ltwZry5iPO2oQZhp0lP8+s8UXM7Ozzjs9WspdZ9COvmSFfSrhg/sCCGnsNUZfBpdaY
         3NK+FK+L1Fd42b+zBICrzKxqlCcbo/m1awHkwjgdf7DhTZzRjYXcjb1kqBTXrXX3BQCZ
         wr103G5dXrnnv2ugbY8xV9M5aJMHWNlcGW077WjKCQC3poJk6xgHV0uLTEvXnyekyFwb
         C10a76ly/3TdxYczX24XKx5U/0kLJhbuNumrkLCnucuOYELYHG6rF124vwOoXpLkKPZf
         8/6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a1eBAKb+IiIssJhkKo3Muao/vVP76nI3R2s5zzwX6xM=;
        fh=hxQgE2U1Zk2mfoHMv1a1sMVWugdwHdwah6JKCpuOVYk=;
        b=j3PC2aJBOBDic7BHYTtjY00TrgoxupWdZmJwyr0FSq/1+BPrs87MZaGOSndIFUMSed
         5o8+EJscpaDfumgEymuZ9lNjJ6REGBotWs3hcJElDsJvVAzPVQk0nGhFN2JKpDj3tUt7
         5Vw8/A9W+NNyp2fyuCVxyHZceIzgy2pN/GkHDaf7kADbzLO0tSGnlIamggPh0129olcs
         7tGUcUZYUTStd+WL+ZQAUBKXlfQrzNWSuzk/Pm2G83lr45J1PMvMn5RM5BpZrkpZsLhC
         tpCBW9hvtxpw0ihEPJL8jtBHJd855z2+aBHrX/Zx7pu6FghVTKo6kzA3lk3Bj+JBfxIW
         8IcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mZqZ6N/O";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a412c92906si426247137.0.2024.10.08.12.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 12:34:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-20b0b2528d8so68563715ad.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 12:34:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXhOGmuDcW7L8Kgyh0dfgqG54VifnQ1ZueGKMn0aBrCIVBlgR6sXW8McPbzNeBCeqqJ3oY2WLsd4I=@googlegroups.com
X-Received: by 2002:a17:902:e5c1:b0:207:7eaa:d6bb with SMTP id
 d9443c01a7336-20c6374711fmr1457145ad.29.1728416088034; Tue, 08 Oct 2024
 12:34:48 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
 <20241008192910.2823726-1-snovitoll@gmail.com>
In-Reply-To: <20241008192910.2823726-1-snovitoll@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Oct 2024 21:34:10 +0200
Message-ID: <CANpmjNO9js1Ncb9b=wQQCJi4K8XZEDf_Z9E29yw2LmXkOdH0Xw@mail.gmail.com>
Subject: Re: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="mZqZ6N/O";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 8 Oct 2024 at 21:28, Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kernel
> memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> the memory corruption.
>
> syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> KASAN report via kasan_check_range() which is not the expected behaviour
> as copy_from_kernel_nofault() is meant to be a non-faulting helper.
>
> Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
> kernel memory. In copy_to_kernel_nofault() we can retain
> instrument_write() explicitly for the memory corruption instrumentation.
>
> copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> kunit test currently fails. Need more clarification on it
> - currently, disabled in kunit test.
>
> Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> Reviewed-by: Marco Elver <elver@google.com>
> Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> v2:
> - squashed previous submitted in -mm tree 2 patches based on Linus tree
> v3:
> - moved checks to *_nofault_loop macros per Marco's comments
> - edited the commit message
> v4:
> - replaced Suggested-By with Reviewed-By: Marco Elver

For future reference: No need to send v+1 just for this tag. Usually
maintainers pick up tags from the last round without the original
author having to send out a v+1 with the tags. Of course, if you make
other corrections and need to send a v+1, then it is appropriate to
collect tags where those tags would remain valid (such as on unchanged
patches part of the series, or for simpler corrections).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9js1Ncb9b%3DwQQCJi4K8XZEDf_Z9E29yw2LmXkOdH0Xw%40mail.gmail.com.
