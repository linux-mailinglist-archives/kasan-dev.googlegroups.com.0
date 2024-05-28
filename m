Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV5A26ZAMGQEHKBNBZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 763448D1B6E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 14:38:48 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-43e1a913c49sf2028871cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 05:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716899927; cv=pass;
        d=google.com; s=arc-20160816;
        b=ESKYDPYQyVo+w8oxUnvoptudj5599G+7ipEzqG0b0DuzQF9fJqqhvY2Xir/12asVL1
         Yqeu1GU2MG/kgqKOPog0WbdKLjlrQ9CgyR8TOibnX5SR212gA6CvmKYHXX4L8Zli9VxY
         AO562tmW2mefBIoesqaW6PlniYKcFbKfQfJcYavjmXSVrUwOhpnKMQD5FNLn04gaC2q/
         avQjmeKqsekHPbkTVUQbN5md4Q96ckQ19Ca0lnrL5ddOl5d3/tm6xvSX0VgL8w9RP63q
         lkBuGum0YWvOEJ8BuQ1vmploPYPNRbPETViVQRo9XwXh0bOxRUUqLeZsmxMpXlcMatz4
         lmNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V5zUe33I5Ys3TZFiAFBeemDLh82xjqvlP6vwp/pT2EI=;
        fh=dz+4GCQwznpUOSRO38EzNtaxktUBejovna7+h/evDg8=;
        b=EObiNRlfzImdfFBBADYJzR3Oxcr2QX6nXCDI5U3pSENi/aA7a5/7ExLNLwxDxtIBny
         UY/eU6w89Fp5kzXgBRbcmqE2+txPnkrlMSr02/T9rAmInnmGgsLi+uHhH1oxOi26FQpD
         zcbGcLLgRAW8iO8oyUeyCg95gYymYo2DwV2NfmZA8HitdmsoqoiE1Q4cDGYXXcbvqzIR
         Irxv23XJZyFZKuO1caZANwqEUYyvRlUIWYCdRVneZ/+MnRbSXW6KprMXU16fGzx6UhTN
         lEaptFRk/DBJi/VnEhunMzaTGplnSQfeUxp7DRE746aJQ32xHM2g9juQFkSOTyxkiwdO
         cYLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Mm17UBdb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716899927; x=1717504727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V5zUe33I5Ys3TZFiAFBeemDLh82xjqvlP6vwp/pT2EI=;
        b=jYMqiYcWuDEG5ITeCoKYLkl36zGxEg9CLAPnjaUsBqvZ9yzfVTVhOkfXKzw7MpsgX0
         Je263QxW/U0uvOE805RRxaLcfgRf/PXlSKHwcok+cxgXiwwCzekP+QWLYWi1WfEgb4ba
         Ez0EQZt/LlCOehpqzeb2nU9vIDZN0HJ1d1ZHs5NtHXUogkWx8KMGAu6JmLuSVihJTcFu
         1c/zKdSeLboUXg1GxEI6sQRWjFXfc8cjo/pFeWqkJK+QgIPSVo25g/weaBx6+N9kmHPa
         dbFoyhpW4SpymGB7m75RJ35fcqBVTQH4Wna9wtCDzTMS5jVq41c6kVFF+tym0sGf4sx0
         wQWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716899927; x=1717504727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V5zUe33I5Ys3TZFiAFBeemDLh82xjqvlP6vwp/pT2EI=;
        b=MhvCbEOFNSsX4ollTE7zVBpAKwZ+TnRXAuillaImfdC1DDO5z2wEPGYz0rvCscCfYd
         pcVtT4M6LQSgUfuBWp0xisgU4sgX2x3PRoLZmC/wrj6lNZnrYCtSdjXc2CvUqIRU2RGb
         ChZ4o6nDMe2MjJ9vValgM8pYsOLKgGoBDEPhFOvmCt+ZSgGdc0i8WyXPb4wjmQK4rkVP
         AsVc6Un1ePKK+BD8xLwb6lPMEiB9EJARe7fAiKxpSo9U1V98M3KDui9HN/uejkj95szm
         oyZ/qO7hgNXt0KjmnPL3zojAvZPcTYTNASFPE/hmagrWi+f4nQrmDHb/VwVpF0cteRH8
         IyGg==
X-Forwarded-Encrypted: i=2; AJvYcCUkJ7eEnHPOSbBGo8omqsik5gLTw9Ff51IN2sqeUzOzuhXFs0lKUAAk0VyYzkLQP31LIZehtBl4KX1lWLIroCB3naghHU4Pyg==
X-Gm-Message-State: AOJu0Yy6yuuEzwDqJuvcocSK388Qa1sWDR9442dRMzeEjYFE+HCO0fPl
	Xvwc6IwufhscoueRStO556yvpPFj/yjNz7LB8jdjt87O5DaaZ4MT
X-Google-Smtp-Source: AGHT+IFmoBo58PqiEc8/0o5sETR+O19nqkczSePdD6GqVXn+5CMyc8kqzMh7cP6fX65rtOtl0f2S1Q==
X-Received: by 2002:a05:622a:550a:b0:43c:554e:b81 with SMTP id d75a77b69052e-43fbb0d08d9mr6287971cf.23.1716899927198;
        Tue, 28 May 2024 05:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5885:0:b0:43a:9717:34db with SMTP id d75a77b69052e-43fd8d7c8dals6833871cf.1.-pod-prod-05-us;
 Tue, 28 May 2024 05:38:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8x+3vbCqyQOTUPEVDYCF/HSSIvD9IsCfNhsnTCvkVdRuMZsnuSpufZNT1BdWVeR/+LqDtnoPPaFDFIVHoV2UEgk7uv8mnbSilVQ==
X-Received: by 2002:a05:620a:37a9:b0:794:82de:c38e with SMTP id af79cd13be357-794ab1108a1mr1140908385a.73.1716899926394;
        Tue, 28 May 2024 05:38:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716899926; cv=none;
        d=google.com; s=arc-20160816;
        b=vFTM9lsU6R1sn7PobW5BZlhoehcpq7ku8MeKeTfwcxPkmHj1JTRX7/MQrIX6hIEYvU
         ijDv9ANJFtHt26VcYdCpTjCOmqKrDQ1ru3KUBwXEHoL2G4VtspEBLNuKUF+VNK2VS9V6
         uiKyDHsohdiKQa+Oq9iXZHoXwu/i0AVP5uvAy7CigHNJeARYdqZA6BO5lMzYtXotqu6H
         hBwauddNTsihgcEYTqpA/eRzRZ6bjOwOkCF2luMopSTkzVWHvVzRrEg02r/tmFU4NXys
         vkCfEWgTzRJix41BRN+kZW+F4reBbNbpDJ3ozAUd1YLm1Z1vhNkVL1u2eOifI8P8s9WZ
         Zcxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K2yOu7S394kYY/a0W/YaDXm8nhL73Hm/MC9DzzKzcks=;
        fh=7YCN3WzCLnszOfxqYLyyPxObV+rIIZcP60ZaqGM+6O4=;
        b=h5eaFmNoWRpfJHxmnqQGST3lkbky49qc/z2H7RR4HgwxAYqOlCoJy5Ntl8VRrJaVvH
         lSE82/lvuaXBr3i239+kQ7yZRueaP9vFyg2nd7GVEe1PidxJpLTx058o1jfnIeGDU0iU
         uHC2EaLGlRrJdD4oTZNZwv1Uqv1+iSziTjV01lBGKBLVK4ZhcRP4brLyjy19PZfeFekH
         kjt/8vADyzxZ2IaJkdg8GG7MMDvS7KJsewrnS3BIzaj/pzaJ3to62Bn1f8OG/WsYQcca
         HdcutWi2cd7NCfU/dZXQSYXh5apTDBFTxhUd7lFxQInHyjTSXwRIktFdNcv6FehtAZiv
         t33w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Mm17UBdb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-794abca9246si33658685a.1.2024.05.28.05.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 05:38:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id 71dfb90a1353d-4e4efcc4aabso294113e0c.0
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 05:38:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAWLI3DG5zczpbEC0Qny/5rEYJC1mhxd0JqdHVLnHe1+pwurCMjtEFNI1KRvhW+M2IAe4bCF9gzLJZ1Idd1xaRM+l/vBGKtWnCHw==
X-Received: by 2002:a05:6122:3c91:b0:4dc:d7b4:5f7d with SMTP id
 71dfb90a1353d-4e4f0283c61mr11666919e0c.8.1716899924298; Tue, 28 May 2024
 05:38:44 -0700 (PDT)
MIME-Version: 1.0
References: <20240528104807.738758-1-glider@google.com>
In-Reply-To: <20240528104807.738758-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 May 2024 14:38:05 +0200
Message-ID: <CANpmjNP=GFdp49Cqa+n3GEC5sb3EWkBaYeMWqwLH7vA=NJyNbA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kmsan: do not wipe out origin when doing partial unpoisoning
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, bjohannesmeyer@gmail.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Mm17UBdb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as
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

On Tue, 28 May 2024 at 12:48, Alexander Potapenko <glider@google.com> wrote:
>
> As noticed by Brian, KMSAN should not be zeroing the origin when
> unpoisoning parts of a four-byte uninitialized value, e.g.:
>
>     char a[4];
>     kmsan_unpoison_memory(a, 1);
>
> This led to false negatives, as certain poisoned values could receive zero
> origins, preventing those values from being reported.
>
> To fix the problem, check that kmsan_internal_set_shadow_origin() writes
> zero origins only to slots which have zero shadow.
>
> Reported-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
> Link: https://lore.kernel.org/lkml/20240524232804.1984355-1-bjohannesmeyer@gmail.com/T/
> Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmsan/core.c | 15 +++++++++++----
>  1 file changed, 11 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index cf2d70e9c9a5f..95f859e38c533 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -196,8 +196,7 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
>                                       u32 origin, bool checked)
>  {
>         u64 address = (u64)addr;
> -       void *shadow_start;
> -       u32 *origin_start;
> +       u32 *shadow_start, *origin_start;
>         size_t pad = 0;
>
>         KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(addr, size));
> @@ -225,8 +224,16 @@ void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
>         origin_start =
>                 (u32 *)kmsan_get_metadata((void *)address, KMSAN_META_ORIGIN);
>
> -       for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++)
> -               origin_start[i] = origin;
> +       /*
> +        * If the new origin is non-zero, assume that the shadow byte is also non-zero,
> +        * and unconditionally overwrite the old origin slot.
> +        * If the new origin is zero, overwrite the old origin slot iff the
> +        * corresponding shadow slot is zero.
> +        */
> +       for (int i = 0; i < size / KMSAN_ORIGIN_SIZE; i++) {
> +               if (origin || !shadow_start[i])
> +                       origin_start[i] = origin;
> +       }

Reviewed-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%3DGFdp49Cqa%2Bn3GEC5sb3EWkBaYeMWqwLH7vA%3DNJyNbA%40mail.gmail.com.
