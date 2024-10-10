Return-Path: <kasan-dev+bncBDW2JDUY5AORBDMTUG4AMGQEUDCGPDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E394999483
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 23:39:27 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-53691cd5a20sf1204846e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 14:39:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728596366; cv=pass;
        d=google.com; s=arc-20240605;
        b=MD/cxmhY1Rg9hb1Cl2dpviriHWCvh+GithoEUYP8EDx06eStfk1M1tZAmffWU0y8cy
         qYsYFOrZPjvp1Aoy3iZrlfsbdl8rnBet3oi62jPiMFD+pUWiHAsjd7z//i3c52jsEe33
         s6jsrV5d3+8+1g9xp8YsZKouWtaTAsEq5B4sHCcAAe60HL6MSmKTIu8/KSk0LYBEaLqQ
         QGtnx7ptnYwfOKlWnYf9qCAlHCsWNIm5waQj4+0nuA3oWj8iLPLYMTzaDteaWpdyzNCR
         jTtpkup5O5akJ4o4L+E+e4U+2s5xS2jDa+GoUiCOmqyvAuOjAkTBhabWBF/sP31ICyWR
         vPdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uq5dva2JjObf1GN/lzirvFvGnr3uTCoY9IaZSeocDMY=;
        fh=juz3JC3OyfnpFN4aNakjHu8w8GR3+9LmT7iDahLai5M=;
        b=O4fExQB5n2ljL3j+4IHkFZqyjfmEMzzo1EoWIhQVYqxtIkVyecY8/7Y1lFtFRQMPNM
         JAYTTUaXcdu7mN/PNCk15q6a7RD2timtJ5kQbaF7NjeAiVaMSptwVKrW+DGTKGMfftSh
         jL2Pm+fFc5+goCipRenL9xC/LIyZQlfvLH7zKFUJFi6Y2NuKsfCu2us2+ftbXk5MmZ/b
         2gsPhFLvxvcx5nySr4zDCC7WpzWqV5KexjnZLIluBotaxY5RJsSoWmGuQjlXX5vjv14e
         Ue48OHj921ECAhymoyLWKydJrE/JpU8ktKL60eJ/iwxorR1FO9L5s6QAJP9bhFlzPdj7
         mgTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AUF4an4C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728596366; x=1729201166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uq5dva2JjObf1GN/lzirvFvGnr3uTCoY9IaZSeocDMY=;
        b=b3f6IWrAEN7WvRBHyXFqiZraqNdY6GBmPUQ6cW+CkJ5mWIgWyrBoHd6OwsBSGmXCC8
         qSRyqpFS/FHG4shPJd9GRckN6sHY3bSLaPCtSMmTiIUBpyWdmiT/U4yVaWKuDcI8Cdd2
         AHM84VfA4DRTX5KaSfeLyYjE9BPgOjLmTfAC/9Dtmnrt2GAtFiCUbvJQESAVJN0m7o66
         8JfqzmdyujyA/TCrrfaEjcc9p9qMXL0/HuSYAPUcQUWUM+cJvWbdP+83CTxN9au3YyA2
         o3GTQ+Rai6S0lNKgcgJm42GK2RgoOdGwEW4G8NNr00YQUZaNmLhRVkG4PcDUpsg8OQMz
         JQBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728596366; x=1729201166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uq5dva2JjObf1GN/lzirvFvGnr3uTCoY9IaZSeocDMY=;
        b=IvgM99RA5gxcwCQtodUf0hKHwWg+ZhwKadkocVR7yPA2B3/tQ/OYhjf0VRVIWoALNM
         d0LWIMsjNM3HfW2Ly4GcQn2i98CeQdm4h/woFVnofRQctTztPC9XiCLMTT0ATqkYWe5O
         R4d2dvmNcAoa2A0JwKwirKAegHq6Lnp3auYMlBR1SkRyucMgJKUFD49yjlELwEJ6Sm5H
         FE8Sowu+dlnojWc9yUETz3gti36T0jg6yLdz8dh048m8jS8eiGU0a+ZaRPp/ZhTEhqLP
         ayofhl1J/Qjj3e9K0kY2ktB13StX8FRbR2t/fkQ898HquLVJy+ncsl3w+X3LO2253Y7z
         vskw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728596366; x=1729201166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uq5dva2JjObf1GN/lzirvFvGnr3uTCoY9IaZSeocDMY=;
        b=lk9DayeRK9c7DBbBUfoUBv6eIRmlTJw6HPSTh3Q9Jo82wJT+F/FHl1B3abnBt7qk0L
         l6XvHe8EEtH76sTjFcE/SLuUY4f8/w6TWWq+YHmQug7jZXqTTOY2Z2dX5/3k6HgfOgpV
         n8i0ad3+wkF5tfUPPabq4F57gfZi2WwsWukUCOQIg6ynPlq2N8k+NA0cGTRC7IIyjfHZ
         aUm/OnsZ9To7AwxbtjDQf7JAdIiipnrYqoB1BlMu2VJlFKDVSKFvoBneGlhRqxkp7/8y
         zWtC8xV0QzfEPtKz7JHqRrDxuHmDb1hJ49A6ajo4/g8oOsRLJqRoy9BuKEphWL21GdFu
         lDKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRXQKnavoMfgcGI2/VeMg8zcD0h00yVFA6DlJXtM2cn9mjZ0mm+RY7S6+/RJOQ0wlsFUFJ7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzqSlt53HdVvn6ppGhdEBNJHZCzNt6kIouCJ/ckk1YbN2kVUpyS
	UNUM73YvjAOUEiUxQltQBhiecix7YKbtqg6mtywtEg8SFYfxJTIh
X-Google-Smtp-Source: AGHT+IH+1Te92WLAo2fqjBhre8Bonu3WwwtbcMh2gC5iChDDlhWRsM+Ti+P8R5QVQJuViZ3VAEIZ3Q==
X-Received: by 2002:a05:6512:1587:b0:539:8876:5555 with SMTP id 2adb3069b0e04-539da4cd035mr139116e87.29.1728596365843;
        Thu, 10 Oct 2024 14:39:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2826:b0:539:907d:1ed7 with SMTP id
 2adb3069b0e04-539c9be7661ls775186e87.2.-pod-prod-08-eu; Thu, 10 Oct 2024
 14:39:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUax9YbNwiKlsCeZQj8s1vDxsLX8a5ZkAZ24Nmtv/cAyRjeMSUfhnEO5sKy4kmKoAeNxKxM14G4B7U=@googlegroups.com
X-Received: by 2002:a05:6512:3343:b0:539:948a:aadb with SMTP id 2adb3069b0e04-539da552df1mr122811e87.42.1728596363556;
        Thu, 10 Oct 2024 14:39:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728596363; cv=none;
        d=google.com; s=arc-20240605;
        b=NsoOjVQtxBRsAVspTasVLS0llltGIjnlBchAfnhnJ+IEq+2/SN6qtVwLtV/Ogt8cn1
         32T7DLXObXnChzAtBg6t+ubD7o7J1ucnqybI46cSEIjigYVb5Q5GJnuaSlPIv/MA+KTK
         CI1Qh5OPhgb7tdPOA6dHclm+5Z7LBEG3ypsFvTUqUJTLOSgzyRrc9G4LKDfLspf0080q
         kOe5rKE1RUvSH3gqvfp2BV38HNVuDl1jt3PIZshHMucraKmOSypmHYIpZxzDViVVdJnt
         UAHhayn1Fq0KaxGKcpkJ4ww7gUPJcCLWscAMcSHaOALT+oLQFpyj2iF+fbdaXqB7rYoH
         5iMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iSmm3ujWM9Lc1PSwYMhMkjrX/ACOqoUCH/T2z1DTYLQ=;
        fh=TkYjUoIJzaJJeIvmjx62qS1Jb6TJnantL62rLsUW0fg=;
        b=hH2+TYd09kTyZKq4lHIsUq0FXZjjJpCOu3v41cnVb9WeuYNcfg71QgeKkwM5pKegq9
         6XjwfLFqTp9eU0dxhE3XN5JZWrd22DWWkHvGmklwxdmvHJThFM7kDTGFvKOyyD4ikqnA
         OsaYUUx4OO2zWkf3yQ0BC0zEuXjrYwUKOKS0sC4hC7giSWcti2QoYgiAq/SdGJ+bHiWc
         5QlSjuvdAwT7+VZJusUezw8ICZA7lyiXiFk4PJB4O384LXf93N7n7KoIa2LOF1KZZB1o
         Q5XtTsR4CnPmNYcY8L1Exr4I9Ab2m3YQIOMeCM3nbBq+gTqo6vow88DOc1Zkd81yg/Jc
         U6BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AUF4an4C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539cb565f0csi42143e87.0.2024.10.10.14.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 14:39:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-42e748f78d6so10387245e9.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 14:39:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWIA2pBWfKyL5tn/YkxRaaQ3woST3+u08f67SJEz30ip+jebqQIgrUzMBxn0kiWrvUmmLhq4SwrGlw=@googlegroups.com
X-Received: by 2002:a05:6000:181a:b0:37d:50e1:b3d3 with SMTP id
 ffacd0b85a97d-37d551b76c9mr259081f8f.20.1728596362610; Thu, 10 Oct 2024
 14:39:22 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNPnEMBxF1-Lr_BACmPYxOTRa=k6Vwi=EFR=BED=G8akg@mail.gmail.com>
 <20241010131130.2903601-1-snovitoll@gmail.com>
In-Reply-To: <20241010131130.2903601-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 10 Oct 2024 23:39:11 +0200
Message-ID: <CA+fCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12=HgB4b=Vv-xw@mail.gmail.com>
Subject: Re: [PATCH v5] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: elver@google.com, akpm@linux-foundation.org, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AUF4an4C;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 10, 2024 at 3:10=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..cb6ad84641ec 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,6 +1954,42 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> +static void copy_to_kernel_nofault_oob(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[128];
> +       size_t size =3D sizeof(buf);
> +
> +       /* This test currently fails with the HW_TAGS mode.
> +        * The reason is unknown and needs to be investigated. */
> +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> +               /* Check that the returned pointer is tagged. */
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN=
);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KER=
NEL);
> +       }

It appears you deleted a wrong check. I meant the checks above, not
the CONFIG_KASAN_HW_TAGS one.

> +
> +       /*
> +       * We test copy_to_kernel_nofault() to detect corrupted memory tha=
t is
> +       * being written into the kernel. In contrast, copy_from_kernel_no=
fault()
> +       * is primarily used in kernel helper functions where the source a=
ddress
> +       * might be random or uninitialized. Applying KASAN instrumentatio=
n to
> +       * copy_from_kernel_nofault() could lead to false positives.
> +       * By focusing KASAN checks only on copy_to_kernel_nofault(),
> +       * we ensure that only valid memory is written to the kernel,
> +       * minimizing the risk of kernel corruption while avoiding
> +       * false positives in the reverse case.
> +       */
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));

Nit: empty line before kfree.

> +       kfree(ptr);
> +}

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12%3DHgB4b%3DVv-xw%40mail.=
gmail.com.
