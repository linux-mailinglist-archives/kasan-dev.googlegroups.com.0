Return-Path: <kasan-dev+bncBDW2JDUY5AORBFNN5ONAMGQEQIHNMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 839E9610118
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 21:05:59 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id u21-20020ab05b15000000b0041117468ea7sf817419uae.23
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:05:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666897557; cv=pass;
        d=google.com; s=arc-20160816;
        b=JEMbj2hhI0Nt/O0belCkn/sPZw2vZXQ2hfi4GFmMPf5BkLLVuL/A/xELS8DwJWZzWG
         o8uoT2Cb5inExJINeHB0UR3kd+YOWgtxsZx8SAmaKYlsRUgvaQabpYuqzsehnz3AKw84
         W//pvOf4q1BO+9p6v6rqTmGAA1lDZdxGc6/8p+qWumTJdtb8ezS7DzoSR+c+UlYyWeGr
         EwGz7/5jUaDMqn79qwjLsGVKMdf0OLLy4GTdqf1Y+kENXa6S1gNKJWtlkZe2Cm7PR3EM
         ztUKr1N5YdS6h3e24udzGAWoHOf0yyYmAvlhRxzxTmqISqdeQ3PnfpHAHIO2f6wIn9Oa
         FA5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jyLXhVj7DHdXQ2HvPfkSnvu58LSlQ9yZDcPEx6CxzhM=;
        b=k6yeKTqSsE71f4btbqUAEeIZy2mtvlOBuLeco/t7sCHV8jLIlJU9SIgpORYSmbcpDI
         CWvpnUH8ME03A5raa4/OBKalVcPYuHyplE4dzT4+vK11Uc1bsAEEWUnDswrxHa5u3cJm
         8uW3+NlSo5N3bLAD2i2wu5ofJuYVA5WGutzl1rhkMDEs5kXe7/wrUiCJF8L9MQ+2hykS
         oFmCFxeFO65g3pJlDUvgafeoLewxD3+0mOtbVBq/hbZ08sH7/cAF9PCLH2EJqUfgBwUf
         Jr/1iehIRGmuuoh6WsEbqMJSqEuBuPXMLo0OFtlAN+P6vqIdzBDcIf0w1mQyfH4GvAEK
         X1sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Sqz2uDjb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jyLXhVj7DHdXQ2HvPfkSnvu58LSlQ9yZDcPEx6CxzhM=;
        b=cabHeMxT/MJ4QVGJV7DLQYvsm4jUsm5S+Ywm8RNuHOwm5aK69lloY3n+yfB8JQjXFW
         I8xth4Avh86NIOgrMe56PS4jBKJpztyu3oTQgkFsDU05i3VYvti88x+rUqggZjvWPVSt
         0gnxM4W6SviwNQqSOoxHjD9oh/f3fDh9Q9e2tHzmq6QoeyBMijloN6/FsnT93NP3bmhf
         zctZ58vHjy0Qed8UKGeXc3vehDCfheGuIM+qhIO8rpwcttCPBuJGQlFRI+4SWI3JltSX
         iOkIFnE/mZ5iIRPMRZvlnD5hqCIVDEdxfpd6LToRQyB5X0ci7PfjelyoQVmJclAAzeqn
         Vqrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=jyLXhVj7DHdXQ2HvPfkSnvu58LSlQ9yZDcPEx6CxzhM=;
        b=mvU/SfAW8IQWsUHSkmdYjiqU7A7GF+wm+RlyAGFnDRR65pDUZgfbXyA3IKGQpI0Z0w
         +D4vejSXcKC8CF/xWyV7rtHyCKQ7SsHpuWKvrAMM1FLMM9BkqtW/5wdf7TQPjJ6jaLLk
         m7eaU394lPGdL41GuDGyigVy+n8Bk/ltUC0tp9lLpC9Vm72kRLIQLvQI9KNS0/viRJLv
         m7fs4+zL03A7Q1cq4KLW1waKwe+Luncn5RjuOS5N1beBJlA3/YD3vd6zThah6VxtAciM
         5POwrpaPnxEfbDkk4aZWa21NUwRiyp3cCLqOP5N9YWzgCsMeR+SLmLS5Sxn7JMwOZl0a
         oQcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jyLXhVj7DHdXQ2HvPfkSnvu58LSlQ9yZDcPEx6CxzhM=;
        b=fMbfs/k1H6ObghGpnE5wEZhw9ZH1qR3ULDCKVD45x1Upqi67GHtuaBuemqvuOCDzXy
         wdemMLcEhlT0Gu+x43fjGI/VDp+S5O9qVyCVL9QZUUg/MbBNlszGM/KigXc4EPFQUqou
         N7DtswAlsJSQMl1VOkhcfdV+fo1cpMRw1dUs3vZLbpL9TNlX0fwO2RtXa7OzDIw3/4iZ
         nB7/HCA88ocVWDE11zn89NOjPxMEd7+kVJO3ebWA9UxydTmSFXcJg8Xnk7YA+6oYYiHt
         gZ7gqVx7anl020ukKFseBf26fvwyOErQo1GI1Jxv2qG6Y8l6fSvpSdgL/gwILtUV4zQ+
         jgNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3F/gjk82FZuYmQhe4gmWZyKxh7WIRMtscp3fMkkK71BPULERQZ
	peIBUKltTQDq11rD9M74wNQ=
X-Google-Smtp-Source: AMsMyM6xI7VznYiZEPIDDNRaQy0qZqp1GjuQg8vWyEaqMNpYxMZD+V4Zd4VxTCjV6fZVoVCq0X53kA==
X-Received: by 2002:a1f:b405:0:b0:3ae:be72:32bc with SMTP id d5-20020a1fb405000000b003aebe7232bcmr26825567vkf.41.1666897557643;
        Thu, 27 Oct 2022 12:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b451:0:b0:3b7:3f1c:6018 with SMTP id d78-20020a1fb451000000b003b73f1c6018ls19995vkf.4.-pod-prod-gmail;
 Thu, 27 Oct 2022 12:05:57 -0700 (PDT)
X-Received: by 2002:a1f:142:0:b0:3b5:359e:8a31 with SMTP id 63-20020a1f0142000000b003b5359e8a31mr13631500vkb.7.1666897556978;
        Thu, 27 Oct 2022 12:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666897556; cv=none;
        d=google.com; s=arc-20160816;
        b=koUU3lM1KAwvr3aD6g5S5cIWM44q7pBF8m69uuW9evzOOQ1W+r2fPNcvjP4hiLljFl
         07NTltue+tuk6zay3JCreNvP2bJeQixLrI7xGV5QL93ZGHPEQj4gfzCB2Ln271efdyaz
         7vdnA7vVeItjt57ifXJBHH/B+1aCiNBQwzg0a8xxBqql6S+3ZbDP8DCKYCeovppoomX9
         mQQMg6KILd8nBslMpjgCgN8U6VrzzwQ82u30xk+jja7xDSWrvcAoYOVQ+Q81oRRdUm67
         M2eclwyNCvPf6+wI2bXIc89IjpvbXiPpwuQMmS6izhiwpFF7aHoSHYUh7YbTkM+KU/Jt
         udMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A1XprAgWB0s7wiMtyLLvIEnH2hN1akKHT1cSrZfMn0g=;
        b=AdaQNiT2xdjcVfSIdC+XtbblL7NcwQAHSzhMmfSEqU2KTbpuXQ4GxvtowX0eifdrw7
         aUG2nfRVHbaon4y0aylxbW/0paeNRO0aHNzQ1m62c+P4UiYurj+WnKU/ONLFJkUFEZjr
         HpEEAtyqOvJ0/qhvCleouGjr0zpk6YODiNB8xVg9Drb3hXZw3Hn2oH0IRF1UKAUxoDmZ
         vn0m42QqHlzaVlGrYN0YJcyhjB5hk3cd+p2x6AC71Css8VGu7Ekqs+alqP/Y5cjbQn5W
         dI37T8F24TqWtQZ5QA/7eUBMIBnZts7lvYEhLSQ9ZJllhDOT+nNRyDQONaEYAsIdWUXi
         oyHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Sqz2uDjb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id r24-20020a67ef98000000b003980b6c8861si109149vsp.2.2022.10.27.12.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 12:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id p8-20020a056830130800b0066bb73cf3bcso1611612otq.11
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 12:05:56 -0700 (PDT)
X-Received: by 2002:a9d:5c02:0:b0:65c:20e6:46a with SMTP id
 o2-20020a9d5c02000000b0065c20e6046amr23632464otk.213.1666897556488; Thu, 27
 Oct 2022 12:05:56 -0700 (PDT)
MIME-Version: 1.0
References: <20221022180455.never.023-kees@kernel.org>
In-Reply-To: <20221022180455.never.023-kees@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Oct 2022 21:05:45 +0200
Message-ID: <CA+fCnZcj_Hq1NQv1L2U7+A8quqj+4kA=8A7LwOWz5eYNQFra+A@mail.gmail.com>
Subject: Re: [PATCH] mm: Make ksize() a reporting-only function
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, Dmitry Vyukov <dvyukov@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Paolo Abeni <pabeni@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Sqz2uDjb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::32a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Oct 22, 2022 at 8:08 PM Kees Cook <keescook@chromium.org> wrote:
>
> With all "silently resizing" callers of ksize() refactored, remove the
> logic in ksize() that would allow it to be used to effectively change
> the size of an allocation (bypassing __alloc_size hints, etc). Users
> wanting this feature need to either use kmalloc_size_roundup() before an
> allocation, or use krealloc() directly.
>
> For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> some of the partially open-coded ksize() in __do_krealloc with ksize()
> now that it doesn't perform unpoisoning.
>
> Adjust the KUnit tests to match the new ksize() behavior.

Hi Kees,

> -/* Check that ksize() makes the whole object accessible. */
> +/* Check that ksize() does NOT unpoison whole object. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
>         char *ptr;
> @@ -791,15 +791,17 @@ static void ksize_unpoisons_memory(struct kunit *test)
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
>         real_size = ksize(ptr);
> +       KUNIT_EXPECT_GT(test, real_size, size);
>
>         OPTIMIZER_HIDE_VAR(ptr);
>
>         /* This access shouldn't trigger a KASAN report. */
> -       ptr[size] = 'x';
> +       ptr[size - 1] = 'x';
>
>         /* This one must. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);

How about also accessing ptr[size] here? It would allow for a more
precise checking of the in-object redzone.

>
>         kfree(ptr);
>  }

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcj_Hq1NQv1L2U7%2BA8quqj%2B4kA%3D8A7LwOWz5eYNQFra%2BA%40mail.gmail.com.
