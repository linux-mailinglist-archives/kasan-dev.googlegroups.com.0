Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNOQ4DCQMGQEZZDGHRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D3E1B41D27
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 13:36:23 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-30cce8fa3b1sf3107318fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 04:36:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756899381; cv=pass;
        d=google.com; s=arc-20240605;
        b=fAcBo5NA8/ED4V6GVWd8o43U3AOz3j6QqNF3u+u/pxxDbb4rjFCrvGTlS6ghNqBKYr
         2SQwKoKtTDc7Y3Y2o94AKlEA9PXYVmC+HRAv4KfHTMtZp3TKQSR4ALTxxlHnQO5wDr73
         +ZZ7gs6Q4lgV8Xfo1YP0ISsa87oKsoH4GD0ardh5VM/NV4ag9Y0K4E46EABpG+4aWPAV
         ct9AfdvJfaelJW7iLRMgSyyKFUZRp0DxyYVFuQUDnZaxbNZVYDpmlyaU5GM/GSKLXWRC
         8BOvZlcSbgCJ/oFtZtTUTuClVXMu+W7yrO5b788lFXr/2kfkl6Fkv0tX32OMDXFK8dEN
         7ZuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JN0uds3erE/AP55wMg7Y0AQOJPyVi/T9DeiDux+Cy/M=;
        fh=kvLPz+8eOZguumunbP1PJk1ZTp0fNy6VGVlMuA4u/rc=;
        b=g0eCBlxzCVs2XHMhaHwPO9pjPVn14zg6CbZ1l0SFkleN/YXkDSiWlc34nNeLTR+n/r
         dQ6i94gpd0Q3vJIngbjMhiR8WjWmqGs4sHjopGgcTL4Fhlmq/qHYxZ+umLek0kPSiTYZ
         iuusNXOW/y+Nr2otG3VLwcgbC4/fRVKseAhgNnWGCpLg/QGMWS20KAOcAACL1MzNWku7
         UvwS5nNXsXvmjAI3u9KInjBoXLVxa9sIt4rhju7zwXBWO5nq8Hf/Cfu+UQl2fozzhSq/
         ZH81hLL8QoXwCLoCfpPdqe81B5GXDTy+idIa2alKa7/ilLud5UeHRdfsUtTxxIJK+UrI
         ONpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EFp8mV72;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756899381; x=1757504181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JN0uds3erE/AP55wMg7Y0AQOJPyVi/T9DeiDux+Cy/M=;
        b=HK4FVsDGdGd4iUdIY1pu85DK1cme3/6iHQOw9bGfKLGxfcnHNnYcCIf0ueQ5030Xu9
         vfjss4tLkBRVewErsnjg3KJ7oTvqibTdwV/4f95LJqtKXLLsX+9aOlqzgnhhlhy9e0ay
         x89RYjf1KqzYMdKAr1fq4mCTIh6VdKwIbglwL9x7xRPA6DkXIublA781iWYZAlPPlaac
         HbPZIxZGSh7Ys3TqatfGtKrd6Tc0koXxvAK2X+xL0Gm+8VwH1hGdQZ5giAA5AFZlJdb8
         y1Lgor2m+Q1ckPffuZ/SHKNx22a5sAYeBccr1OwTN8yV6p34hu7pMof2oIA96AE80Dx8
         /8iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756899381; x=1757504181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JN0uds3erE/AP55wMg7Y0AQOJPyVi/T9DeiDux+Cy/M=;
        b=pPk2Hb8Sxogby2dNuiL0FwKhGUIzBlKUI5zzo3A2ABz1tuVIjHtziTtyaFuY1Mrnts
         VRP2H7aOuEcvXIQWHs6Du0EM8FnVVv5LPOkRBV/2N/U1h5KPU3IVNf3kj6fW8DWPWTJL
         juh1O2uN5B3yyPJCNoxp7nDngXHNo3/7Kdtf0DUJ6jV9Fw45GibkhGO8qYt7XhPQUGBe
         KkP7RZoo/ZyDxF1FdGp55G3fXc+1RbilLjkx3ZjNe+tQiyWS9s8+gQJDIEZtOlAcgfH7
         vIUAu4UVMfWlyhE/8dS7tJN/qc18Zk2A94/eiBwxysxBPGnf6bqm5P9qnGr8+w0iWFqG
         vPaQ==
X-Forwarded-Encrypted: i=2; AJvYcCUv7CXxb8IZ2nDkOlfgBK2XogAgNabT5tavSjUdvnprvlKnIFd2MTp6QhEqp8Fev5qAfVpmVg==@lfdr.de
X-Gm-Message-State: AOJu0Yyq9+aXR0pNl4iqSzZP8Ejn61vezQPx2/3k0q/tn9AFhu76KVR0
	dor64YLc2scB7bp4I9Y9GStAIRybxTAK3Kr8cXuNaArPEzfIXR5RNabp
X-Google-Smtp-Source: AGHT+IEYE+eBr1M8+f/1Eb+zh4LVx5zijPJEEnLdCfUmX8gNGBTfCS9sdJQJXvn17ZrQvYQaU9/6YA==
X-Received: by 2002:a05:6820:620:b0:61e:7189:365d with SMTP id 006d021491bc7-61e718938d7mr805585eaf.7.1756899381322;
        Wed, 03 Sep 2025 04:36:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf9iQFtoQLN032BASEZwpOuf9dmIW/aSEWsu0wHORT9FA==
Received: by 2002:a05:6820:270d:b0:61c:1311:37ab with SMTP id
 006d021491bc7-61e13901a90ls2309776eaf.1.-pod-prod-04-us; Wed, 03 Sep 2025
 04:36:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUii5rRDbfKqxkAilI8okCF1kankvFK56HrwGTjtL9/CaijQdIjYto+a6V2P/1BgXOeGemrVSJrfrw=@googlegroups.com
X-Received: by 2002:a05:6808:23c2:b0:437:e31a:b342 with SMTP id 5614622812f47-437f7d71f6dmr8372911b6e.26.1756899380317;
        Wed, 03 Sep 2025 04:36:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756899380; cv=none;
        d=google.com; s=arc-20240605;
        b=gZ/pTBYQ4lF+3G1lglUzZydgcIvtsQgYaczHYk2VWzg2gowW6juNkZ8EwnEXLsQ0Ex
         dIWERfBA4hL2pxIeI3QaF+oY4lTSXBuiDXAWJLwfk2NFsoPTTz/+tr9vet+XAb+Abbxy
         G9zqJOmnFe5aMTiq0eHJoG7qnXBZgUiw43LYVXpeRUjJxgJCrdQ5P80ibWEenRCCz8SK
         mkOrXI0ltDIEtP6uSFbS77U0OJY9SivHMr2smk/osI3Q6Ov3Xs7jAtM88ShlQkr1ut1C
         kP+IvLHqj9GYOZkZM02fB6RlSbHgCxXO44X91l2TDXcABIvyuNMA857ItQcQPsr0sCqX
         TsfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a3IW4gClMpsxg8pegPHxJ+hydJ79H7ht+ce7OmUzWyQ=;
        fh=oQby4yTXr267Gw/AOj6tOwYkVDRB5QVXj0v+ZBcEykI=;
        b=F7sDzcRF4jw1GzgftKAR/YPUvI/QnCHNrCFjL+GzkHy7KLEaS5O6YogHjWCanUxuUL
         liApRYG35u3eRw0XsmLQUYNRB2nhY1CR/JYQhemD0Rz0uC0jLqlKVBokhwO3JOSHZes5
         Bp6s71y/KQZwuJ/GgF1y+w2UeNqlV8uXNgDIGoOyUKpa084tM/XMrGARasmzqtNXuPog
         4srUvjyyzkPZdU9ocRQaLeUWORBdkAfNPRr3tRkuFLpEftJibvMDVN3MkSEFsWfdIcUU
         BOBHRipzAiogSoiagTmV09+4rPLJBe6u6oPajIUz+G8OMrMGoCxI/Yha21iLGqht6nq0
         yiGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EFp8mV72;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437ffc66fd2si343735b6e.0.2025.09.03.04.36.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 04:36:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-4b109c482c8so114185261cf.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 04:36:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUKfrIOqRqHu8Mvl6NKILSTqSXgwVzzdcz9JBqN9x8gQ4cI2m6ls+4QhG0fDqFMZafirtW9dsCkduA=@googlegroups.com
X-Gm-Gg: ASbGncu7TQLYvB3w1CU1MQ9VNzjaIzlIwm+POoAK0KWsUK58mb7lUG16GWYZXduSYLu
	s40eKhuomdsw/4Eb+1GKe+1JpyeS8AmD3hvhu0b4/0UdRbHkvHQI7NqdY3ro9YXdk8ltudtZyrD
	Tdw/T9crTxyy64IuqwkHCk9z9GnPIaG3nWGuBQjjd2UxqW4HZouuQqC8bceLzZkQG3vuMlKyxx/
	k4gzUIjmUo7kzxYjsqYFj7FnF2MYFsVXqjXp+fxhXQ=
X-Received: by 2002:ad4:5aaf:0:b0:725:1fb:a6b6 with SMTP id
 6a1803df08f44-72501fbac03mr16948666d6.31.1756899379536; Wed, 03 Sep 2025
 04:36:19 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 13:35:41 +0200
X-Gm-Features: Ac12FXyA87fTSQv-blZ3tbQBrKQAAZ9Bwbod18tXQa26iNm899ybg0GqU8LYCbA
Message-ID: <CAG_fn=U+xi3zjr+g+PaT_41JHSca1W6J72xd5=c0dVrSy75XpA@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 2/7] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EFp8mV72;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> +       static ssize_t kfuzztest_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len, \
> +                                                     loff_t *off)                                           \
> +       {                                                                                                    \
> +               test_arg_type *arg;                                                                          \
> +               void *buffer;                                                                                \
> +               int ret;                                                                                     \
> +                                                                                                             \
> +               buffer = kmalloc(len, GFP_KERNEL);                                                           \
> +               if (!buffer)                                                                                 \
> +                       return -ENOMEM;                                                                      \
> +               ret = simple_write_to_buffer(buffer, len, off, buf, len);                                    \
> +               if (ret < 0)                                                                                 \
> +                       goto out;                                                                            \
> +               ret = kfuzztest_parse_and_relocate(buffer, len, (void **)&arg);                              \
> +               if (ret < 0)                                                                                 \
> +                       goto out;                                                                            \
> +               kfuzztest_logic_##test_name(arg);                                                            \
> +               ret = len;                                                                                   \
> +out:                                                                                                         \
> +               kfree(buffer);                                                                               \
> +               return ret;                                                                                  \
> +       }                                                                                                    \
> +       static void kfuzztest_logic_##test_name(test_arg_type *arg)

simple_write_to_buffer() may write less than len bytes if it hits a
protected page.
You should check that `ret == len` and return -EFAULT if they differ.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU%2Bxi3zjr%2Bg%2BPaT_41JHSca1W6J72xd5%3Dc0dVrSy75XpA%40mail.gmail.com.
