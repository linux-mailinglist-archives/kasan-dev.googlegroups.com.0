Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBV35DBQMGQE7PXYX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 05865B0A060
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 12:10:18 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-74b4d2f67d5sf1821187b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 03:10:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752833415; cv=pass;
        d=google.com; s=arc-20240605;
        b=NpDTM+kklyXmHBzIld/T+6oldN/j5KwTwKXN69ywEJTLZQCsY34DpadPMciVaa92H0
         gIiJEhlfT00BjOv4RVCRmqBunkcSfshbFcUmsUxqNgfw33ls14Ay923km8EbDye1x5PP
         GbYifs+8D9pagLDB+RUS9uVyvIzv0Ij/glwG1IBcf4WeZrewl3xtFmWHkzhXmkgVxpMh
         NgW2yuxKiA3ynZczhfvkfLWz9f49g5QaeQf6iTjlLtEfOqvY6cc/f+7GN4M7r+BXE2AZ
         TqmORbWZbYpDXTp8ER1B5Nt2qWi5BbPKL0KuGW/NqVSXFcQsxuPSykWhLFPFccp5x2DL
         aVIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qkhZ93AQZqx9CwHvsjUstVO+EKsnpK7x/MYxkJef4Kc=;
        fh=mNJTrBd8NxXLtcCbxuG1wcKanlwW9bH6kaR7+FVHuhA=;
        b=egCFTr0kMvKWpycBQBqnwzxxDyaciRtxrHqTCJiBAsuFfuQ/4z9prVxqkGWWtUqTtJ
         iANhNAz2nR/GSidZ8QOYH8R0XU9eeFhZFwCn6w4DKoaTRCMQ+XCudErpXkusCgxvQ7UW
         lF/3dUMGpBymo/7ZeWYaa0vUpm3nWp3iNzs5cEw/C1pqXuhatCLt6vBNx8s5K8teKF0Q
         GchQMnLWVWbzdJGBP3zuQGvKgFlDbcgpifjrJSO2frRF56AK8sSYBPKIOHNDYTZIhspm
         ETgYkqb/2MraY8DBhnP3UeH0AilxsqKpSPoHe5qs+T/XMUKdKwSh+ok8KllPyRVOvuKL
         7J3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQlcndFd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752833415; x=1753438215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qkhZ93AQZqx9CwHvsjUstVO+EKsnpK7x/MYxkJef4Kc=;
        b=Q4UxkTjRl4ebWfJ27xZm6HMBqiH+0Wrz3CtzQSvZc/G2QnMWb5Pcl1EwwR0Cz5cwk4
         JJZxrl6VN1wvlD7IG4Pw76l2lNztZWiWuT6uIEAEqxMsPR2SgMvtyHpsMke/MPkCiC7f
         /Scol8zxNCoo3TfO4c2gienEdqLQQJzEhyOGhFesWEm4jVMltkUP+r2JJ/Fgkh14s7Tb
         DX5yJCWtg2+uGNcUs0ksue5ME42EPcEKJsaHjGD2q3nd1ENRp93PK14L0RpnjESe0dio
         tflYV+m4OFzXmLnJvtzfcwWI/Ui1K/vtJ9NmbK/6WjRgfdDqFDEXWS3gY+ov6/2w5424
         TfvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752833415; x=1753438215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qkhZ93AQZqx9CwHvsjUstVO+EKsnpK7x/MYxkJef4Kc=;
        b=TimMR/q8cnVoIIQ2KGuG7RsEpjcqM02xpDDcY4Z9pAOWR1vB+NN3YlBeCGZxk32G5a
         8Cfv7VFNwqp/ubbaQ612oGQBR1tjS9LCjp1FKtCkV7+sDskvXb6Y+jNpVn5dLWZY4GRd
         /r5D4DwJmuVDwiSbH907yJcRxDLX+PnBntdOih3wEG6xY4KRl7Bq46TZmFTZsEmk738P
         uCpRaCrP9063dH8UsTb5QZ+jH2guqtTcDzOR7qQK5jwE9oXGSHFzJ3xLGmRt6neJV+uI
         6NzGPoEwn4nxWHdojX06DabtTIrGTqddfK3sQ+nnQwdt8HM/fV5tcdr4gxhmmkZmg1TH
         1Hwg==
X-Forwarded-Encrypted: i=2; AJvYcCUhUGhb3ZVd9T9A0OxV3yrWqVBdJFNUTx4OdPEuIpj10M5W63INO4C0p684ejsKCMgj+LphpQ==@lfdr.de
X-Gm-Message-State: AOJu0YygFvUlbb3hyHPMDwWG6MHPIlORtf4g3fznETf9G+as5Txjn3L6
	pct5rLcgjJXFRLVGV/5dmsQlts6tMIEHezK/lZ0YsImg0woQnuueeQx5
X-Google-Smtp-Source: AGHT+IH40vS3JHm9p10egQrS4f8bD14DqPEC/DzYi7fqWT9upqfGOfb3x2wDrkNcI9tXTzKFdPZbiA==
X-Received: by 2002:a05:6a20:9381:b0:232:e727:bec7 with SMTP id adf61e73a8af0-2391ca91582mr4036181637.41.1752833415268;
        Fri, 18 Jul 2025 03:10:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdo8wBisd4m1TfPnAYw/tpmMkaktthpyWhzmZMrLJaKWA==
Received: by 2002:a05:6a00:c87:b0:732:d98:9b2e with SMTP id
 d2e1a72fcca58-75823402551ls1857849b3a.0.-pod-prod-04-us; Fri, 18 Jul 2025
 03:10:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJLAmO5T3Wyx9nsKbeEtS+Ejvm3j7hqnyGBgPbBUmrXHvAlLCggrLu8v6/kUh7psIeC2wB1jsnw+I=@googlegroups.com
X-Received: by 2002:a05:6a00:240e:b0:736:8c0f:7758 with SMTP id d2e1a72fcca58-759ac02c4cdmr2900373b3a.10.1752833413620;
        Fri, 18 Jul 2025 03:10:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752833413; cv=none;
        d=google.com; s=arc-20240605;
        b=U8GdPT/+51b2HgQJ8IEprOOhN0yrbBJh3jHHg6cSlU87cy294vH+kq0SX9QBmIeafZ
         1tiqe60+1erjUHg8l2Y2nDD46bPKqRZIgSZydbTTketzCb/nY9ODbE/Ca0ZZCrsx0T6O
         21FQm81TilBEk8TIs2QOXZNFL0DM3VBHN4bu+7PjpLSyURS9HZQNT5ABgI4NFvVGg4y4
         fU5cdJe+XhvEw49XQrjyhPLn0iYBtGAUJD+ydoswyR3kR2GrYglEjUFVwi8kSNPo0+kp
         z+eirEgMOh1GgNiNtkgYHqagAX/0sjuu/Z8cay0RsUJ3LCkyFlIsc5L6CS1hWfoMDXuv
         iR8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jEPCqIH2/jSbx3GcTZK0ApZM+EPW/w4+Xq1YOqzaECc=;
        fh=g4zC81SpJjDjfJwcCzi8c02d2BNuInJXFu6aj5e5fvM=;
        b=TWrM+wqCNqkmknptMJfVyzsGR6h2T3rxdSuNNc/ETuSZ1VivhxxHyQDtNZog/G+aM7
         /XH9XWsS//Mib5rs+8jzSbaneuCifXrsFjKwrU6qFuvcBlR6xsV1nQMlxqZVhFrawgBR
         RrbWOU4DX3/iZMXQOtYgpASh4THPBTx+jMV0FydnZqyAie1Uf1WsvIjDc/ylbR5Ya4pc
         OOrBmc3AtjeGYGbo/E2c+M1bv9gShOOMjPAbpJfazBYiXIzI9zJtmBCct0/rn7QLprbW
         x+0X5mCB8DPuPRn6NvKv8pL9YFsAeMkZF52emYSIZhmIxaKtd1VJ7Zp8dDb8iyNSvmt+
         edHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQlcndFd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-759c7bcdc96si54329b3a.2.2025.07.18.03.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jul 2025 03:10:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-701046cfeefso28985516d6.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 03:10:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGdivIVsDkvrIzNqIJjX7glQaUULocSmyplCw8obE5ISl9eJzXaMHOvFI3Rk5Yjl5Q/RlK8VLcY8w=@googlegroups.com
X-Gm-Gg: ASbGncuBB7dJBhJIjVOUerq3ltUW75vtNFmQJtYczo4Dv7+n+wVnbRNcXo2A62a2K1R
	zLtCTROwH4oPv7LQ9gLIjln0leY/8CJ4iZxyBPqc1/RJJemw3zyeiwrfSHBkh6bl3CrxxrWN+y2
	h/2xHAG8w+ZpTKGVSTsKm2qqRlNXZ5qKmJNMzVy0beuMZktGP0DqZRgyxTyEuWtpZCu44jdildK
	v1X30s1CB7ZHu7IlHO+4ecK9tLxcRi6+xDf5Hw6JWBkNDg=
X-Received: by 2002:a05:6214:5192:b0:704:95c6:f5f1 with SMTP id
 6a1803df08f44-7051a15125fmr34835966d6.34.1752833412173; Fri, 18 Jul 2025
 03:10:12 -0700 (PDT)
MIME-Version: 1.0
References: <746aed.1562c.1981cd4e43c.Coremail.baishuoran@hrbeu.edu.cn>
In-Reply-To: <746aed.1562c.1981cd4e43c.Coremail.baishuoran@hrbeu.edu.cn>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Jul 2025 12:09:33 +0200
X-Gm-Features: Ac12FXwsHM_uuBa1qVrE5Gm7fmdma5LXAF-jfsts2wnYsvJPRzKuXDI3yQVqq9k
Message-ID: <CAG_fn=V+3kgtcvv5J9FZ+jf12SDVhcdwxnada=b=UuXbu+2v6Q@mail.gmail.com>
Subject: Re: KASAN: out-of-bounds in __asan_memcpy
To: =?UTF-8?B?55m954OB5YaJ?= <baishuoran@hrbeu.edu.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Kun Hu <huk23@m.fudan.edu.cn>, Jiaji Qin <jjtan24@m.fudan.edu.cn>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dQlcndFd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Fri, Jul 18, 2025 at 11:19=E2=80=AFAM =E7=99=BD=E7=83=81=E5=86=89 <baish=
uoran@hrbeu.edu.cn> wrote:
>
> Dear Maintainers,
>

Hi Shuoran,

Your colleague Kun Hu reported a use-after free with the same stack
trace in May: https://lkml.org/lkml/2025/5/21/611
At that time I pointed out that this bug is already well known to
syzkaller, and there is little value in reporting it again.
Note that the out-of-bounds report is also known to syzkaller:
https://syzkaller.appspot.com/bug?extid=3Daa6df9d3b383bf5f047f

Is there any particular reason to report the same bug over and over again?

> When using our customized Syzkaller to fuzz the latest Linux kernel, the =
following crash was triggered.

Unfortunately the fact that your customized syzkaller instance found a
known bug doesn't indicate that any of your customizations work.

>
> HEAD commit: 6537cfb395f352782918d8ee7b7f10ba2cc3cbf2
> git tree: upstream
> Output: https://github.com/pghk13/Kernel-Bug/blob/main/0702_6.14/KASAN%3A=
%20out-of-bounds%20in%20__asan_memcpy/11_report.txt

Both this report and the stack trace below lack the file:line
information, which usually urges people to close the email.
Please refer to
https://github.com/google/syzkaller/blob/master/docs/linux/reporting_kernel=
_bugs.md
for some suggestions on how to give the users more information.

> The error occurs around line 105 of the function, possibly during the sec=
ond kasan_check_range call, which checks the target address dest: it may be=
 due to dest + len exceeding the allocated memory boundary, dest pointing t=
o freed memory (use-after-free), or the len parameter being too large, caus=
ing the target address range to exceed the valid area.

This is clearly an LLM-generated description, and a poor one. There
can be potential for LLMs helping people to understand bug reports,
but when working on a prototype you'd better check every text that you
send out.

> We have reproduced this issue several times on 6.14 again.

There is no point to reproduce bugs on 6.14 as long as it is
reproducible upstream.
If it is not, the best thing you can do is probably to find out which
commit fixed it, and notify the maintainers that the commit needs to
be backported.

>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev=
/746aed.1562c.1981cd4e43c.Coremail.baishuoran%40hrbeu.edu.cn.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DV%2B3kgtcvv5J9FZ%2Bjf12SDVhcdwxnada%3Db%3DUuXbu%2B2v6Q%40mail.gmail=
.com.
