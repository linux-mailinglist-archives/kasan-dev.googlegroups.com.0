Return-Path: <kasan-dev+bncBDW2JDUY5AORBVG5VWZQMGQE6DJZSMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F7F7907EA0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 00:12:38 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-422c0c00762sf9963065e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 15:12:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718316757; cv=pass;
        d=google.com; s=arc-20160816;
        b=asMbnUfmXGlfjty1q9u8Ga2+63oR5UYWo2KMzHwtv0+MBTDNfr2EMCGwL+1uM+1PgG
         Tn1ZL/uddLuPc6IHFWwBgAEGIuoJ/f8V9pS1Z6tUsf3G06ZOps9tXTeMqjiFSrrKZRMR
         tampvcAeQZQY5qgQH7rPrgsyn+NarzHLYgXCvSsa/IXBML4WChYdBnzrQFYgD1dnYdVI
         B7KFir/DT/nO5ATqXd4BI3+mvIvPuF3+O86r6GJ1z0xzJjCunGWIXA4/hfFFAw7dR3iB
         uRHHp2rV2NXKIgRurLJSkfUGi7XmzTG/hQAn2/Rs2Ll/6yXfihKZhgbEnP9kw9Kq4f/Q
         Qi3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=iRQ5kUMlwngcf28X2mmqHvmQ76PcSAtBYnnczrNA8Y8=;
        fh=Wj8uvQ2RtdpAa2tSLYFxPH5BWMauzuvj+KKZWHHSuhg=;
        b=WPECvduzAJCW1b2IxIy6ecUZaqguxy4tHnufMcpEEX6eOEbGiAmtLNKLIxPLstoMHV
         qSwfpfqjoxQqYK2GJ03BfQvYHmzrlwu8lUwq3YbX7U58JdFjqY0a671K3T+ITM/csJR7
         KaD6tMEsa3ZzusFsscIPzEXnncMrd6zSbnxeEmtdiAXvJb2ecfZwDFordvmVR+E0zTCG
         N1trY9k8vurUZeoCZzO6MotDN+VArnUc41unk6Rb4pXAKy74h1no/UhGgQz67Km3X7PZ
         E3wNizrGP3TxmiPa/2UY8Je3DxaPIIApVx5yciFcRxf+/dV72d4I95/cV/5tLKi8TVxp
         ikMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l4IThLhM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718316757; x=1718921557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iRQ5kUMlwngcf28X2mmqHvmQ76PcSAtBYnnczrNA8Y8=;
        b=kjVYNQ8JLT0mNYePMFCgfmr2hp9b1Zrq5u+kkJgbhS5rMCTuU9cNMx+Kf6wjbxHmLv
         5xhq53kk5q19+0oFRC/YpwH5/Y7nlx2KaTiy0/eUYNVb2a1xL4edkYMNClJye63ENAEt
         R99LtMdFnykywM+mc+GRfbYQz7qwgWofYvi+5vpToo/PwwR9IzD8dZGvui/coCAv1Top
         uVzHT/+RnN0DihaqtIg3NFrskTE/guwvIIoYjaBfDlu5aFdM3ossKKp1RMU7VAGr+BpV
         pJLcoXvZ53S6woP4RnXfDag6VOrgkYxfPy3Oa7VsDV2ToCh1wQr+w2p2NHukLgGUOQo3
         KTlQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718316757; x=1718921557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iRQ5kUMlwngcf28X2mmqHvmQ76PcSAtBYnnczrNA8Y8=;
        b=etoJ0vkScwY0bT1pFYtZdMKZfBq88bFU+c/7zCwbUXKD4vOiln8vfJ04Ao6jKaEEkl
         N+ppgNHO57Hb6JburPiU2P4N+QAP+e7ML8gOf4gr+GE+MRoi1XH8JJJlRqLwcPurwfiI
         PQ3m+62EodH5WPa2mxb23LXqqC7fn6JZJDsD1EvREZjIhuOnrUYnz3UxW6h3br6/Mp4v
         6jWddoMTzcnEHj9lIQtKbvY7bVtlAdpFiYF4Aw4/3Qahg5VKeHp9Wuz++ovUGoHPxNh8
         MXA9Q0Cp0/bzcPBKU6bbmYx5ZfVMOllrTFnKzkK6UzHnunay3AqjKv/QSyMQvHTTG6qM
         wiXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718316757; x=1718921557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iRQ5kUMlwngcf28X2mmqHvmQ76PcSAtBYnnczrNA8Y8=;
        b=wazNpjqPaOo/nR6nsJqEJ2JjNKFCQEigKsi6ABzb2HO4Wm6MIpZ/7xhCG/9y3Ej/J9
         xmXzfH1h29AeyYKOlbaxtQZ9YnCUcoDRFMy7u3rVDtJJJFE/0qCVM9lwoVzDUlqV4gz7
         us8O4Py9vnbTerOnwzbCHx3dcmqwNigD2Em+qtaQtdlxU67tpv4tTfyvlPcfNfLeqs7X
         QftUMDZ4HL1fDrZwV9FLeOF0NtbHm1k4kJqrj21AOyR1viBdRxUp0lMGd6YHyr0F/kwm
         ottaaMavEeDk84Guc7SaPhkXpBxN2OW5Co+8AUQtoaW+sHWbYZIsaADiEwVqmJjwyhwS
         iWvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXaucAOyPXap9FG5BhITCCUoSAaDN0ecYyOdoiumwGUATCpZR1gFpixx54Ft45rk/NHPgv2LsXF56BtC+EDpouMrRk+t2NpTw==
X-Gm-Message-State: AOJu0YwPGgsmkULWGQPH5n+mo4+fLCWn2H+k5zd7MmaKyT0f27f4d30l
	0j8BaS6B2clWHppl8/2iJThuWLajphzlI6/1i/o3A8Mz9DVkjW5c
X-Google-Smtp-Source: AGHT+IGSSZ4C8YdDyk8qloaes4UzVSEpKAH3Rrs6IyUupMfcIq14X+Iliw+h0QSoappLQps0FDJpnQ==
X-Received: by 2002:a05:600c:a08:b0:421:8e64:5f72 with SMTP id 5b1f17b1804b1-4230482bcdcmr8076805e9.18.1718316756745;
        Thu, 13 Jun 2024 15:12:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4346:b0:422:cb6c:76b2 with SMTP id
 5b1f17b1804b1-422cb6c7806ls5326055e9.2.-pod-prod-04-eu; Thu, 13 Jun 2024
 15:12:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWm/9ccf8OEckD7+/onQHJQbVLyC/ML7hxYsROqXYnLFXkJarWFUybxu/ljP+w4vzvwFFgihiKCwq87dbFc8RsF4Od72S/n3WFzGQ==
X-Received: by 2002:a05:600c:4191:b0:421:7e76:b85c with SMTP id 5b1f17b1804b1-4230482fbf0mr8631005e9.23.1718316754788;
        Thu, 13 Jun 2024 15:12:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718316754; cv=none;
        d=google.com; s=arc-20160816;
        b=0klIo9w4ClPLTEzR6n72DZEodrT2BDTCFlpS8Ejjh41NgLxXY9IYcH3qIFboyn5f06
         DKR63SMvSEK6i1YjjWog8o2oXTmCO3Zmd79labA1uz9F/xuRIJjlPNYB3GctyNZ6/t09
         sPbpForRvIo7DCaAWev6DpBi2v2hD9sTwdsWuO95DU2Tf8SfX7ktVvye9acEXNhsxByO
         7GGXXWnC5Ab/46+7mLkNyVcYqjjKQfvRlh4lNvmKfP6eSFqIpIzrAZMcGn3DM20xNFwG
         RsFqO1RdoIUT51ks4RyzyNF6oY4gvD58xK28pldCUefC32cCIq6+2JobDzrV+nk3JHKG
         FSNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=me4cz2sH6K4XsN9xxV5NWaQHOePrLe/rCqne2IhtkQI=;
        fh=D6zz3PGcoZ3P00RJ4yluf+HTHg3HIBCbmXjSY8JX8sU=;
        b=mVtxZyqnisibxuas9EohVZHnl/bGxYykhUORYZr3O5on1CM+2qKmDgVQs9IrH53SIK
         j2vFi5AJlAuKVgemfS3IqGlX7i5TVgQpZhyuqE42hAfQijK7wrSu5khu4J4GI1pRfyEJ
         QkqP9S/kqtPQW54NyywBL4OhGhKZKMAI/TErrMtbjR8p5HOurzoTY33hhOAZKyB2mPaf
         pB1eRvahLWREyyMeRIwu51qhrS/6PoDeHgH/7dQByTNXboo4iWNuR7tyYX0G7ARb2XDA
         Kvh6pjKT/X20AFsLVHSCR8vDf5a5fhP/SQeCOaF9oZmsPJuYJ0jotTxVm+jriuM5c33N
         tM0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l4IThLhM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42285317d3bsi3444785e9.1.2024.06.13.15.12.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Jun 2024 15:12:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-42278f3aea4so15496165e9.1;
        Thu, 13 Jun 2024 15:12:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQ4/9WhvEgKw8LIkbZ2MIlZcfT7QtiCHhcGc8Lu+kex7jTp3t6WbwqocjL0RXmzh5JcSTIrZ8Qmzl3sl2yoZAAieo07lul6bdC2ysn6WommgT4qif3Cchv9DhelwZh2XOicCGr0jw=
X-Received: by 2002:a05:600c:3d86:b0:421:9fc4:7973 with SMTP id
 5b1f17b1804b1-423048272c9mr8941605e9.15.1718316754107; Thu, 13 Jun 2024
 15:12:34 -0700 (PDT)
MIME-Version: 1.0
References: <20240611133229.527822-1-nogikh@google.com>
In-Reply-To: <20240611133229.527822-1-nogikh@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 14 Jun 2024 00:12:23 +0200
Message-ID: <CA+fCnZcDE4YyfRNM236duuk6kmOhCrOnpW0XvwMHY+vgVaqbkg@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't lose track of remote references during softirqs
To: Aleksandr Nogikh <nogikh@google.com>
Cc: dvyukov@google.com, arnd@arndb.de, akpm@linux-foundation.org, 
	elver@google.com, glider@google.com, syzkaller@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=l4IThLhM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
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

On Tue, Jun 11, 2024 at 3:32=E2=80=AFPM Aleksandr Nogikh <nogikh@google.com=
> wrote:
>
> In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
> metadata of the current task into a per-CPU variable. However, the
> kcov_mode_enabled(mode) check is not sufficient in the case of remote
> KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
> for remote KCOV objects.
>
> If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
> happens to get interrupted and kcov_remote_start() is called, it
> ultimately leads to kcov_remote_stop() NOT restoring the original
> KCOV reference. So when the task exits, all registered remote KCOV
> handles remain active forever.
>
> Fix it by introducing a special kcov_mode that is assigned to the
> task that owns a KCOV remote object. It makes kcov_mode_enabled()
> return true and yet does not trigger coverage collection in
> __sanitizer_cov_trace_pc() and write_comp_data().
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
> ---
>  include/linux/kcov.h | 2 ++
>  kernel/kcov.c        | 1 +
>  2 files changed, 3 insertions(+)
>
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index b851ba415e03..3b479a3d235a 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -21,6 +21,8 @@ enum kcov_mode {
>         KCOV_MODE_TRACE_PC =3D 2,
>         /* Collecting comparison operands mode. */
>         KCOV_MODE_TRACE_CMP =3D 3,
> +       /* The process owns a KCOV remote reference. */
> +       KCOV_MODE_REMOTE =3D 4,
>  };
>
>  #define KCOV_IN_CTXSW  (1 << 30)
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index c3124f6d5536..5371d3f7b5c3 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -632,6 +632,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsig=
ned int cmd,
>                         return -EINVAL;
>                 kcov->mode =3D mode;
>                 t->kcov =3D kcov;
> +               WRITE_ONCE(t->kcov_mode, KCOV_MODE_REMOTE);
>                 kcov->t =3D t;
>                 kcov->remote =3D true;
>                 kcov->remote_size =3D remote_arg->area_size;
> --
> 2.45.2.505.gda0bf45e8d-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for fixing this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcDE4YyfRNM236duuk6kmOhCrOnpW0XvwMHY%2BvgVaqbkg%40mail.gm=
ail.com.
