Return-Path: <kasan-dev+bncBDW2JDUY5AORB3MPVC3QMGQEPPWQGWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B83EA97B5E9
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 00:51:26 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-42cb22d396csf48384225e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 15:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726613486; cv=pass;
        d=google.com; s=arc-20240605;
        b=NCuhUsbKAj/IyWbHoWKbEw2hxGJpYw/Cd2HaqbWL5HyeHyFDm2p+D9K4MCFV6CueIQ
         eHgVeFibZRs5lDhMRn6vyO6fHxQ6CKptHRbRjeEXo5B68GAyaQZXqs+fuWm390/rGD7q
         SGPaOj1mX7q6Umxqf6vADg5W0t7S0qKmZkN/Idzl+kwmiMFeInQyokHkkYUgV73X4Yco
         1/bqjWoVfV7EFPCi0Yjbc0hRBnCUHGo87xCWtD69HPqIQnmEtifwibbvNC2hNwFgkFVF
         hE91T6sC1wY6fxkHEtzbFJfT7t0glK8SxMU1XdGjMblFMZOcjUtW4kuzgc0ltGmXHdgH
         p9Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=b4iHO/GirL3UXwaYgyiLQmMXz3QiRmJVbMUnFNdUtLE=;
        fh=YvlMFaWdnA3vqDUVC++vtmz0qAZkuuXl2jzAFfDUAVY=;
        b=iG7CC4DS+s8SkhKBPTRtZfSx/UjwI65EmparQJKRfSARdJXwSIo27cKX9xHubdoDrC
         SsHyo/8Irx6T1NvXqzmSC36mnjpG0jJmNa6/GChzTSNJtEy7x1jmnDCoSrC3lhNE8t4Y
         HDorhgMSJhCsbimXO1gXHb7XJA7YKWKo2dyqQ06TeWCYup7nE7xp+ZPSF+kx06UAJRq1
         nSwncIa93j9wUpDapU1PLw3RQcT73wlKWiwI5qJjJPoCZsRvWUNWazFSxd9XPF+kO+24
         tswgw3p4udOHIxmO9ah13c01s4oZoay9nDSiP94fjT1R5tk4FPqzukeBmxrWW8J228cx
         Q0BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="KcoXL/lN";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726613486; x=1727218286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b4iHO/GirL3UXwaYgyiLQmMXz3QiRmJVbMUnFNdUtLE=;
        b=wz7N1lkzbd6lJuJk4TKoeB86iTq78Yrecg822JFvi8HVnzZs4dNUgyMvim+7u/F2zL
         EGja+UIh/OWGfyeooYFXEluxNCLmQ0S74zZ3ZfGa9GaPwaCCfhdFuZmDnBK20qRuZpja
         Vns6pSZ0Ff3uXR6cDn+FbRjoMKowC8YQsQcnse0Zysxgz1LDw5PsyHP1aO+G9urgV6wJ
         rV4LWpW6cyJO55bcfEfYztQBwUc7tLb+n7AZHz3sEbHX10FZYMw+riiCqcmhtqGGqPm5
         7p7rUrry2Okm3/5StC315XnQdwA7+80fFNeUqRk04ZuWi3ZENTTpjziBzkQFi4kD/g9/
         iPcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726613486; x=1727218286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b4iHO/GirL3UXwaYgyiLQmMXz3QiRmJVbMUnFNdUtLE=;
        b=gCPcV+6IYd/ktrX2XkNq13z/zNqC2+p3kwpqUfgW7zYlwip1JlUR6QnQOQXC19lj4F
         5pwxN8VXZY5ch0XNzzi3QZ5F68nKx98uDfjGzXY7HuI5EVnylZzQxCVDYkq1iL2zOS/s
         m8gHjbW2HnZY2usuKT7Qm29TmLQYzaBWX/HQQ09d7thT5WIj9cQmqBU4r2KBOIZkYddF
         DmFiQLO5O2/Yq0/O8zc65+piFkd3YRfCyeWCKvL0BVmnNLGgV46mRW9TiLkKDEjXsqtk
         Rdx5hZw1ob5ZGA14v7/q6IxdjRy1FsiO/MKSkYBMyKPGwKk8MfWsulWwDK8hhOM1auED
         cttw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726613486; x=1727218286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b4iHO/GirL3UXwaYgyiLQmMXz3QiRmJVbMUnFNdUtLE=;
        b=jRxulB1fhywe/0FwhCvn4L/G5zIQFppiHTIb3m5r9mhBj6jHySUg1qRvo5D/CKBqEr
         xsaGTtwWxqg70LAxkQyTdPorKI+CD1NiJC1F6tfTLv+3u+EMUtpOwoILlgN3zi3Bo+xN
         OATxN/Gc1Zvi6wJEdpOJzGp4DW80E4vdSn4keggtYURGotIKHsMR49KyeyAFDMA4D+6I
         G71s2Nhb0gTfYiZsSGof20wA3flb0AS3CK6CfDyFH49cjR6bdSJtvarymIiHmeuQEkJq
         OmRGypxrD8Kzr9LuK7mJE5zRN4Zhuc+e/tGP7xeP1a9oVI2jP53hirMRG1gi9S78WWKJ
         uB7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH/xpvVnpVfpAFzegfEU0fqsUqCV+2UQ4lje3E2eLfeNmWR22ZES0gxphYjgdBH2uFsx2L2g==@lfdr.de
X-Gm-Message-State: AOJu0Yyl+2Mh5m+faSx27D1dL6rq8+dsBWRc/UI+5N3Wq8pychREVpeL
	kNMYeQmDPK55pZyY9KK7k/G77kSB3HtEWbiblRwhC4lUFjeWK+h6
X-Google-Smtp-Source: AGHT+IENTC4ceIWAxBZ+niHXCnpw3Rq79PCC/6+oCxqiXQZWxUTaDRly5HLxncu5MBPKJ8ns5kPT8w==
X-Received: by 2002:a7b:c394:0:b0:42c:df54:18ec with SMTP id 5b1f17b1804b1-42cdf541c13mr166399245e9.28.1726613485460;
        Tue, 17 Sep 2024 15:51:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:45cf:b0:42c:af5b:fad1 with SMTP id
 5b1f17b1804b1-42cdb4e68e6ls3656395e9.1.-pod-prod-09-eu; Tue, 17 Sep 2024
 15:51:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjcmp0UOrg1ZgqGNFQ67sdPgIaRVFaS03igTanSY+rLdTW8Mm/IJa/rm+PAXby2b/qvMYMpmdDWko=@googlegroups.com
X-Received: by 2002:a05:600c:1e1d:b0:426:5fbc:f319 with SMTP id 5b1f17b1804b1-42cdb5783d9mr142760945e9.33.1726613483651;
        Tue, 17 Sep 2024 15:51:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726613483; cv=none;
        d=google.com; s=arc-20240605;
        b=ZAr9sZZZcyMSAYAOfPbHUGkGpO4W46CbUUYDZwEa9EOU5VdlYgexASb/1btIvgdllH
         O1LZMO2sXVKarXia9QC6DLLzIhqpI3RzjahqgrMMTfFerfSVlMoyCSoO9xAWcL1KmbDL
         iHQx2bhQPk37d5mK2lH5ycTVawu9beg14S1ivjaWg6qJdZr+fTQAnwotplY/TLcuwTya
         z8zE1+QbJ+HNr9zyiM6cvfQo3K86CxPRnfeZQf3ckcHIHSKq+tLg4XIVnY4aZhJXJ7yu
         n//jmFzei6YpR5JmDSMqtit47Kt2xNLZOeSL7pmuAer/7IH+7A8Zr/G5Vy195JrJXvWo
         62bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zGebus8PHpfHDtzBPw4HHyxPsRzXQn85I2IG0X1v/b4=;
        fh=ES1dYnztVS5Kgd8sXJe4r3FNvqU36mBMEJhnRlcRpEc=;
        b=AG3D2/BdkRotbGD1L7G8Y1oIPqMHuyRwEi/o/i33ozE468eKQPpNbkxbdzyGipSKLp
         6duAJHWQ+0J1IkFIQv5IrHymei0HZJddfunnZnqd/aMoiYEzVDNXp2VCwAM4T9exgzrv
         8+DTh2XaSayxHOWphJbjyA9KFMft7dvS4CrBhgoSqLW9nUApRP6WueXIL7BRbCCB+MU3
         YAQ1ebCG/9wiQjATVYKaRdmwyO+BFzGxa7Z/PTRVtYlg7NSaq9RjHhl+uEnnvc/oHlkr
         dcy80x8MtPaiyj0cfRZmBeLJ19FTsSaGgoW0bAQ85bCDcBdsOVVIVbrN5GlcnsEuGIwb
         eraw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="KcoXL/lN";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6c719640si1220485e9.1.2024.09.17.15.51.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 15:51:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-42cb8dac900so60029355e9.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 15:51:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBV70sDVzVN5KSpISqJ+b304xXxi8QidK5vN5m9YaqDmDvtYgR7n/JgMMFuw4rCIdeTfGMboycTEs=@googlegroups.com
X-Received: by 2002:a5d:4811:0:b0:374:b9a7:5ed6 with SMTP id
 ffacd0b85a97d-378c2d064c2mr12804597f8f.22.1726613482785; Tue, 17 Sep 2024
 15:51:22 -0700 (PDT)
MIME-Version: 1.0
References: <20240917201817.657490-1-snovitoll@gmail.com>
In-Reply-To: <20240917201817.657490-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 18 Sep 2024 00:51:11 +0200
Message-ID: <CA+fCnZeorA7ptz6YY6=KEmJ+Bvo=9MQmUeBvzYNobtNmBM4L-A@mail.gmail.com>
Subject: Re: [PATCH] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: tglx@linutronix.de, bp@alien8.de, glider@google.com, 
	akpm@linux-foundation.org, mingo@redhat.com, dave.hansen@linux.intel.com, 
	ryabinin.a.a@gmail.com, x86@kernel.org, hpa@zytor.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, brauner@kernel.org, dhowells@redhat.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="KcoXL/lN";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
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

On Tue, Sep 17, 2024 at 10:18=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
> strncpy_from_kernel_nofault() where __put_kernel_nofault,
> __get_kernel_nofault macros are used.
>
> Regular instrument_read() and instrument_write() handles KASAN, KCSAN
> checks for the access address, though instrument_memcpy_before() might
> be considered as well for both src and dst address validation.
>
> __get_user_size was appended with instrument_get_user() for KMSAN check i=
n
> commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
> put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

Hi Sabyrzhan,

Thanks for working on this!

> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..f5086c86e0bd 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1899,6 +1899,22 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +static void copy_from_to_kernel_nofault(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[16];
> +       size_t size =3D sizeof(buf);
> +
> +       ptr =3D kmalloc(size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       kfree(ptr);
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_from_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));

I just realized that the test I wrote in the bug report is not good.
This call will overwrite the object's contents and thus corrupt the
freelist pointer. This might cause crashes in further tests. KASAN
tests try to avoid harmfully corrupting memory to avoid crashes.

I think the easiest fix would be to allocate e.g. 128 -
KASAN_GRANULE_SIZE bytes and do an out-of-bounds up to 128 bytes via
copy_to/from_kernel_nofault. This will only corrupt the in-object
kmalloc redzone, which is not harmful.

Also, I think we need to test all 4 calls that I had in the bug report
to check both arguments of both functions. Not only the 2 you
included.

> +}

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeorA7ptz6YY6%3DKEmJ%2BBvo%3D9MQmUeBvzYNobtNmBM4L-A%40mai=
l.gmail.com.
