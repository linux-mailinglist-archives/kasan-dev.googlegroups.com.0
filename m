Return-Path: <kasan-dev+bncBCA2BG6MWAHBBG4552IQMGQEV4BHP7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF6914E5A8C
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 22:18:19 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id h14-20020a056512220e00b0044a1337e409sf1013350lfu.12
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648070299; cv=pass;
        d=google.com; s=arc-20160816;
        b=UoXqC1De+d2vqJ0dLiPCKbA+/RBJqdCnFDoRdoMaVWsHzgPtplPQ8z5ShS8eSQppbt
         e/H5POpuOi/TqosAfT0/8TTFzB7Q2kgMo9K+m3UftB4NLBzhqxFKAaP77rsLqjoi00ri
         NhImQ3TQfJbraZohWGz6TUREHymyem1GauLfLT+fjLCuQ4p4DKD6+2XloQ2t8LiYxS5L
         t3lShSQgnnS9VpvJFPsBC2qBm1jLdft7/8Pnj6HG/p97o0A/OzI3Q2vFIxFQ505ysmfg
         jDfwLkP8xq0SMEKfVZPReUCgAFRiWt/lju7aGjGfU5OLOW5f8oQsiJMkBxdUeilQv7oh
         QlbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=erw36YCFfASVp7J2EkPRr0L+jvLoVUSqEltvlstekac=;
        b=ZtvDkRjKqjaW1f8t8UdX+HqP00kK4KA9LykCyKvl7BN4pDLTHzJc2dGRbZqvpiMmqb
         9PRlrnI742oZYDSKj6G2eOFsAA7GIh8zdg17qGavq9b7GC/RZQwZ2d94CDjM7I+Y95nD
         C2JYFAA8lNKLcnx/Ay9rH6/MrowTKlqmTAfa4Un6PAGooXLGNd+BGwcDjClisSfyTx7l
         V6K8cbLzXGb9SH4mBQeuP1+9FtsovCFBpCmHc8+6ch/MKoCp3texGDP7PXQEU07KEQIu
         8F/+Z0Pug3yhC/L4qxL7f7JLNx96AQgPhD1//vn+w2gxv/mdvZnTfrzVJg7a+/eVe3HM
         WvSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UbU3Ichq;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=erw36YCFfASVp7J2EkPRr0L+jvLoVUSqEltvlstekac=;
        b=aIw3I65d4vQnt0Qd4N+zvgsUQ+PeJNsIC4xnQF+sAZ39edaDbGCI1G/k9WPUVlu2u9
         1rrKRzWXOylkYED/yWMKy3EhDMK/llhX0gqmz0++VDyS7RCfX4m+2ZSbiFsAcp5Z9k5g
         FS0kDvgh7qtf6Mhc6ns6paZAX+T1ndS0SkR/IJ/OFHguCjHxgwmQt7sst4k9RVSNsiG5
         chWiAYIKa8XX/jmAOwYcPO/qVsHReel5muORp2qPjtYsDfXyfZa4n8zkhHbxydWW5qqt
         eJxC5OwetHUQrCeqgnR3R4PdSwSLTM/SKTK3kx0wrKAlmBuGBoczNsbDy+maE7euFLLg
         PF6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=erw36YCFfASVp7J2EkPRr0L+jvLoVUSqEltvlstekac=;
        b=IfGRMTy1a68k6SSSDufZW9aesGR29JZEuCpE/k6K5LtG6qR3UNVDdowTaVcgfvjNrr
         rpsndIRuLql+tixwEE/CvBYEW5DQeY76RyfHzI4aKmOCVKHFtW+zkFvRxGqFkdpYYdBD
         /Di24yF07boW/1RO9LqAtLi9qodUD6eYqryXulQTQdTIEZ4J/BObOqGSFdOUTpGvhWKy
         eiGIdK1GfkNUo+P0jMkyczMdNE8BfvepHvrit++fZVxvaCcJz9nCq1PzQvhTRyqwh8YW
         sMEgn3KSfAUQZdtFWAenSYf6MMt3MPdqvfRQLD9sD8jYGMp9b9iX/cP9MWQ/8FI1WaSZ
         p4qg==
X-Gm-Message-State: AOAM531EWmTFu8htc8y4AeMHfdI9M5vPaZgh5yJAbY2Jb8JM4tyvPD8B
	0d7VSXKvd/rvQC1Y/iEuawM=
X-Google-Smtp-Source: ABdhPJwd6fuglUXlDYN1iCZJWflPpGLpwtvrg/9raAKoueBTBAKBtiIawhH0kZyKZ8WgSgXLfeKMMQ==
X-Received: by 2002:a19:ac04:0:b0:448:7cf8:c5a3 with SMTP id g4-20020a19ac04000000b004487cf8c5a3mr1375955lfc.65.1648070299333;
        Wed, 23 Mar 2022 14:18:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als50242lfa.2.gmail; Wed, 23 Mar 2022
 14:18:18 -0700 (PDT)
X-Received: by 2002:a05:6512:2307:b0:44a:5f5c:3d6f with SMTP id o7-20020a056512230700b0044a5f5c3d6fmr241492lfu.307.1648070298408;
        Wed, 23 Mar 2022 14:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648070298; cv=none;
        d=google.com; s=arc-20160816;
        b=guVzZPbPAATBQLzDRNI08TwhadGeA4/VHYi4ZacTUaSn25hJ94VUpGJ4XDUZjaWA7i
         ZsaGDjdhTdKaE7w1AW7jM7s/PlQOz4ilTllDsYgeFqegGOwu5FN51AS9M26ZBfWjDNdp
         5zQe8zbHzuEy8qPuWYLNtgJI43EErbIkfg6Eqj8hbs5oR7U06qQauq2FWWVKdQyRRhQt
         DHozCGVwLF8M1Bxo5r6RRueQ+R3GP+vaY/Q6lyrfbEy2/EVzzYH+Utpb3iZRvHyv7bcr
         IXuUSpd9PoYOB4A5Uiha4xULN/20kdpRm3+OSSrd98e8NCVGb0matcwIqYLAI2rbKrnY
         ln7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z1Qm/xWajAQvpOZlmnrukkZ7JdrDgtUoxCQlGKyuh5U=;
        b=UdVsX8ZC3fz/doFhxfyUGw5zICW1/sxtdH/7ZCKLW6SJLJ96vC0sSXDRKn0hv6YrCX
         WmvaDte/3/NNF1B0E67I1KRShq3BZnZLVaST/g4NtZyJMT0krLyuUF2KZY0G6NZA60uf
         bEsOp6SJlvMcUG7SZxesC7H/Tvu2a5hczgwT4fHEun02z7s7XkPUCAXeU9EBpQecFnp1
         n0hi8MkKmc6zxguzEsqgTDtTzirB86C+XdHw6zPMjaYwlsrxP7yEX7Tuic/8FR/tcbgA
         rysas8eCRfVW9V4fEFvZVT+05O0RFr82B2qcBxIiBriUWk5GE6WtD4yWD2L/D3rBMyeR
         3Mvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UbU3Ichq;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id v7-20020ac258e7000000b0044a5dd2be52si29274lfo.13.2022.03.23.14.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Mar 2022 14:18:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id p15so5390537ejc.7
        for <kasan-dev@googlegroups.com>; Wed, 23 Mar 2022 14:18:18 -0700 (PDT)
X-Received: by 2002:a17:906:c14b:b0:6da:b30d:76a0 with SMTP id
 dp11-20020a170906c14b00b006dab30d76a0mr2199044ejc.279.1648070297760; Wed, 23
 Mar 2022 14:18:17 -0700 (PDT)
MIME-Version: 1.0
References: <20220211164246.410079-1-ribalda@chromium.org> <20220211164246.410079-6-ribalda@chromium.org>
In-Reply-To: <20220211164246.410079-6-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Mar 2022 17:18:06 -0400
Message-ID: <CAFd5g44Rcb9bJyehjqW29wAvaY0hQyDmPWH+XJfN_Hu+=2Yrcg@mail.gmail.com>
Subject: Re: [PATCH v6 6/6] apparmor: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UbU3Ichq;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Feb 11, 2022 at 11:42 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the PTR_EQ NULL checks with the more idiomatic and specific NULL
> macros.
>
> Acked-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44Rcb9bJyehjqW29wAvaY0hQyDmPWH%2BXJfN_Hu%2B%3D2Yrcg%40mail.gmail.com.
