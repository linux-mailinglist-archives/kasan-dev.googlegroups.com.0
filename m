Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6KZ6ZQMGQECWO4E7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FE7A90FE68
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 10:15:13 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7064777603fsf257062b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 01:15:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718871312; cv=pass;
        d=google.com; s=arc-20160816;
        b=RMyX/JigMzYRSdtNp3xdjcQXJgbmMOqkoURK8/B5HHiO0hh9cxbQ0ajFs/rkQNtrIH
         eHWVpbb7O1Jweji1KiMtg3HyG843OIRneXEx0psrHz8+5CIF9EqMDKdu1yx+XWPbH3IZ
         ugbdWtQWZol1c7FiCE/RJlCxfL2d0ryP2Ib7W+cplSLz6FxnJla6W+LTraRO5k7twXvf
         YNefrO8j15ND8UPVLAZbiMGv/s6QjJ1q86UCr5x5AWkmLSgxkfRDMNcTXQ4OwEA4120R
         s+nWjjsb2ZzGEvGddOunVDq6lVtXF0ykuVm8NmtXFxVDl/yOVZJg76Wz2+hJW8/y+v1B
         zv5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+tTwqSpQCAnU8ZgZF387GLfy5wUJ5hXtMn9mJagsPEM=;
        fh=KPSOnWRSEHeir5o8GCM3u8ImdWZnmV0fb4RUj3p8/9U=;
        b=LIscQnekYjkg+/bcyX52xcO6GDS4ijEgTG5uMTt/p3tvL2eyi3suMMlW+lQVWT7GiV
         qnTdW0rAV7w0D2/5ijlrjyHsMNkIBSyimPkox9Eu5IjZA0QQk9qIahE1S9ygaomKo8Pi
         WCx2DwFGDM7eGaLgTfU/jEv1+iLMtuKxf7LW1O9+2o/xFBXiZ7cptOAmRy+0dGIokWlg
         e4r8dW5aB2GW2khB13eeaCsWo9akITk40i88N3sSz46Ns3yRApMz/WMiH9/qrO7igfsd
         FZYPt6qcNMinan4xDnnHIdDLYx1s2JyEnUnIapMmrI2Rs3YJZyjRKQKF6Z5A23iPWTxv
         219g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hbUZIEy7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718871312; x=1719476112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+tTwqSpQCAnU8ZgZF387GLfy5wUJ5hXtMn9mJagsPEM=;
        b=VtBQyvFCnm+jH9BtKXJYzPSpNV1TsxIJVuxxVbohuVQJD94oo9OML0f3bz/6b5x+Nf
         mj8IAjKIF1CJ2QRS3mdN5ps8ltJDCkCHju0YOKFOklWnyhQK5vEeAEz7pI08Ep0pf6nH
         fxUGrY9gjjHJZVd2pI7oOKRJcZu/HxGEd0Egnfh6sGrbEaKqVKakeA5+G7f0v+dxo5Ab
         C42L3NGVRzudXlAsAkHxIMTzb7LjXSzx1x8VhCpTpTu7CHswgMGhvqdVQU9QDFnMtEJu
         NF5nOeeeHeWGORhDElffUiKKIwHDQBeowlXACVvs2yAjedIJb0bA86K36DB5zKdMfpwE
         XIFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718871312; x=1719476112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+tTwqSpQCAnU8ZgZF387GLfy5wUJ5hXtMn9mJagsPEM=;
        b=Vg8wb5agDmL0G6090h1wEfd5Dh98MAQaGNvaX77OxaqSwhWFix5WAcSjC5U37zVy3I
         cq9Un7bLPrFCQfgpP767JYBrkOKYk1iF7Gu381RK3GLCxJNp3fyP8EUUJQ2iJzApFqtK
         3KjCxr7J6dvleq+RewwWLDyFwn+FJEGn4Ixg6HTwVP5IrKPxXiHesnWcEqUG5EQr0C77
         MWQpr6eqVT7q7AVq4mv5ZVVhllLbO6T1J/nnFdkdnMoScwzYlSFL7W4q6IGAjfqighHT
         byZDBk/0LtftNYLYEYx8G8hWLmn1waAyyavmPb7O0I6bRLW0gpCNV7L/YbyAf6w+w2W5
         BGYw==
X-Forwarded-Encrypted: i=2; AJvYcCX31/d3n14wVKOOYVLHvxVWl6LRm2LNBLS74l44W0vVIe3JTGmvJJmpdz2IFkepvopmeMI3KVLwyQtmma2HcP/AzAgB9a7Ufg==
X-Gm-Message-State: AOJu0Yynh+ziHDSgLj7riHu+p3H3FShB3kX4zW/bCSbK+PrHtcBWNThk
	2MmEIarAWW8MI26cTc0y5tN/cE7RnxTAfpq0F3TbZGmFUS3BXXrF
X-Google-Smtp-Source: AGHT+IGrN8b2d018o2okHw7B5stC/8lKk43ycrJChLPeoQySPMMb3qpmVLaWmq0qkZNYnoagNGYYCQ==
X-Received: by 2002:a05:6a20:3b93:b0:1b7:d5d5:415b with SMTP id adf61e73a8af0-1bcbb6982femr4291798637.57.1718871311681;
        Thu, 20 Jun 2024 01:15:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17c1:b0:2c4:bfdb:3038 with SMTP id
 98e67ed59e1d1-2c7dfee1a5als420387a91.1.-pod-prod-05-us; Thu, 20 Jun 2024
 01:15:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvkl5Xamvvyuzygi9HNXp9lxe/88aH9LcGzpQsdBl68kkFCA1NZLdmwCnE4oTzfL92BH519TeolCMy1f90Sc+PBX6E4tKXVw5n8w==
X-Received: by 2002:a17:90b:955:b0:2c7:b112:9d32 with SMTP id 98e67ed59e1d1-2c7b5da567cmr4555963a91.35.1718871309589;
        Thu, 20 Jun 2024 01:15:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718871309; cv=none;
        d=google.com; s=arc-20160816;
        b=DOLn2AG4PRaaaHImb2ZLnJP+HbLZZgOurlqZtbscGsmGusr/HgRmLJRCU+o+6xmt3p
         C9IFfRf07Lr0dq5W+sM/jBfZAwg0t7zbPe9e5Tx1uG0BMDrLR/xTZphJSqoOo9hQBzww
         Paktt71MCUC+ANktqnstx0Ebhifo7Z3QXkE2od7FnrpTPFPQDfcNkiVH3GQsglnm5I8+
         9/rSv/f4cC4cCM87BXvQPNWyHaDjn6wu+PIZ0GNLgf0vpzzQK39zzE4umN4rrPt9r37i
         4+ytohX+duPbyKH/7R3aA1YuEqYD5p4Qsg8w5ul6APSvMVBCz6QYwcrHkrtUQ7kc1Dmn
         ztPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VkDyjmmo2mJ4eSIsOzioTK+npaxfD4Q0PqQ0hVQZ66Q=;
        fh=cgZM6x8n4Oxs8mlirszhz21MUTuenmBLzsK1JlJzKpQ=;
        b=PTohqpcJAsuMFDDJJeR23bXSmz1u8XjvasYy3253REyVRbIPFVXRPbsmQmybWjV2Vs
         IbCBVemnKsx4ty0J+WD1vjBv8CWUt3rIjUjccPSUaqwRwU3XFG6cBvg+rihnrq2Ab8RH
         /RMkc+973AyU0qdr4NvaRrn0eRdt+Mr/rC/un0tq0/4aEN9APi8GEmja85MF9W7Xl3T0
         NExnJb8tQiTtKglnOG0G77HKXIS9a9K8d5fHPfNqNELC5GjtsNsl+vT5DR1DNsNwXHZY
         AHLdroEL7G4HemDee8jktc0M5cHpiIrrhSFLD3WL/aRRSz5PfOeDRDDGGrAMTfLuK2Ue
         C5Cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hbUZIEy7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c803f5359csi4224a91.0.2024.06.20.01.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 01:15:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-6327e303739so5805787b3.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 01:15:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMqgIo0+gyoBcyWOs5y88DpzB66trijNNFWVzXe97NHk9r/i53k/Giv0xYs5e37PaZtwf25JfJZAtAtoo6uRsR62Ets380Bq8WjQ==
X-Received: by 2002:a0d:f185:0:b0:61b:3345:a349 with SMTP id
 00721157ae682-63a8d44ac47mr43240177b3.3.1718871308642; Thu, 20 Jun 2024
 01:15:08 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-13-iii@linux.ibm.com>
In-Reply-To: <20240619154530.163232-13-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 10:14:27 +0200
Message-ID: <CAG_fn=W6L0Yr_GLHEok=LmL0-whk2r+-E7fVHj8pA8GCtgze=Q@mail.gmail.com>
Subject: Re: [PATCH v5 12/37] kmsan: Introduce memset_no_sanitize_memory()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hbUZIEy7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112b
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Add a wrapper for memset() that prevents unpoisoning. This is useful
> for filling memory allocator redzones.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  include/linux/kmsan.h | 13 +++++++++++++
>  1 file changed, 13 insertions(+)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index 23de1b3d6aee..5f50885f2023 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -255,6 +255,14 @@ void kmsan_enable_current(void);
>   */
>  void kmsan_disable_current(void);
>
> +/*
> + * memset_no_sanitize_memory(): memset() without KMSAN instrumentation.
> + */
Please make this a doc comment, like in the rest of the file.
(Please also fix kmsan_enable_current/kmsan_disable_current in the
respective patch)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW6L0Yr_GLHEok%3DLmL0-whk2r%2B-E7fVHj8pA8GCtgze%3DQ%40mai=
l.gmail.com.
