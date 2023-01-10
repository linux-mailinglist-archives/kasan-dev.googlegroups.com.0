Return-Path: <kasan-dev+bncBDHYDEMBWALRBA7B6OOQMGQE7T65XGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A54F66385B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 05:58:45 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id p2-20020a17090a74c200b00226cc39b0afsf4201605pjl.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 20:58:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673326723; cv=pass;
        d=google.com; s=arc-20160816;
        b=hw9JJzuaD5UmR/hXFojTvftvqPRCPszaZnf2A9SlXhdlDCIW6wJUXlpYT2JYuQOG7Y
         /zaoljX4ngOorFxkT10FZ+dDgobzzfYkA46WY31nS06YXn4OaZS7TqDsnL127DR1cDPJ
         NmOBovf15Owb8aPJ67onsxeTbJ/jXwDmNAlQuDWBeoBM+Jng4iQ48KLvGx4GgO4eTL5V
         KpujJzx+3MExbZI2abJvhAc5Lxaednh5edTN+UYux7IPUPnaa3UlLzTLw5KYokBJ9n7Z
         WygVroOQhAcHDQ7DK3KsBxOVeI3ntiag2WbfaiGua86XDP6pwrzOp/+i+4E3rjxURoNx
         2Y3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=bcLcnfITNhgfouke5hhYW6GroD0LG8fO7giuuoC4lKs=;
        b=qbt3lvQYDtoNNxJUdEMUWQp2ZT4YsjcpSL68vM3Y0TlP8hr0mgUL21HuXJvU6Qb68U
         8pAWxTikM/+wwDniLURZuoXf2SiDPmULAZFmEwuDVmx5LveG8iXiVC7JsvqQfo6EqssP
         YNhtsw1HGO8UVc8PKETAfCZj236ZVYVkprSfU7rVeNnUurRz/Mdq7NZCkUFvGDT/GDsg
         /GS18CoADwNjJbQ5gqjvFSX65nyQpC55V7bD63ZIsMYCDuKlglks0ezCuCnJD6csIH1S
         vE/cY2ZHENfV9HBDHSBdtgKw1C6nFuiQQdIoqZKpb9DSy97FBFnC6vCXaeeQtRB/Bz6k
         zhkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@eskimo.com header.s=default header.b=CzvlkD0w;
       spf=pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) smtp.mailfrom=nanook@eskimo.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=eskimo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bcLcnfITNhgfouke5hhYW6GroD0LG8fO7giuuoC4lKs=;
        b=csr2pSAJMTgUnLO40mvszoN5FXuB1Ub7WREJzpLR/jJ9ZcpJs9NtXe15PqIUT8nb3w
         f44Suzrr9L+gJrLTQntmQKjytlYWFdGseuO90vNs43LTJeE4eU974ivHq3rUWmeeNrko
         1PwgLUFEGb+chjCmDou34fXh8A3p0NU+KI0PXV1z5OXG713sXgrMZxfeD3SesUgSXE6Q
         0z1f9mk/YtqQUX/5nI7Xf9+zO1sDiAwYPrbozv+xKtkpqDgW7gPQZcZ96N1G4gIyOn+T
         SQR3QwIa7OlXnyuVlC3fYUjDB5mOfehNyEpEyMwJD3rJwAivUlfBnlUApTWHWW9AUHpz
         3mmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bcLcnfITNhgfouke5hhYW6GroD0LG8fO7giuuoC4lKs=;
        b=1qBbtcoMajuD6gyRkdWdvQ7pHdvXt5JgIy1YjHz23VL8aUSEr3URrLyjsUQNDDU4xp
         1emI42j1VoW9NsUNtyfmPHr+YAFSM8812q8N3Gm6OJ5JatFM/BuquNJ21P8djV76SsKX
         4HaLr9mdm36kUgm0L842W8YfiI/GLm5TZF4KWPHI9ju1q4505C3A8h4cWoeSspGeuCOW
         oDDB+X2+ggqEcrigPi3UcNtb7oWzIecrXN5+givoiNLV8A5GHAuKqYaGeALXNUls/tmv
         b7zxdli3tXc4nglRLNnuKqL63vKZU7pVaXzpm4EQ5xRaXs+LD47g9uro02RGft/uHMk+
         xTHw==
X-Gm-Message-State: AFqh2kqtcSp3eyuTPpvWls1Qin8CPSazG0zNnjmnMJ00XVQFsekCIHtu
	GzIyIfLeS1wIiDam2kB+XrU=
X-Google-Smtp-Source: AMrXdXuqSZ/qL3aY+t8r+qqR6MnLKKlB4lerLqwzCPYDcdPb3c5cYtLB9kFXsfLiHNDrSVeAM89vmQ==
X-Received: by 2002:a17:902:e0d4:b0:192:53e3:6418 with SMTP id e20-20020a170902e0d400b0019253e36418mr4316793pla.90.1673326723464;
        Mon, 09 Jan 2023 20:58:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4d0a:b0:219:84d6:9802 with SMTP id
 c10-20020a17090a4d0a00b0021984d69802ls11345847pjg.3.-pod-canary-gmail; Mon,
 09 Jan 2023 20:58:42 -0800 (PST)
X-Received: by 2002:a17:902:ebca:b0:191:117a:414f with SMTP id p10-20020a170902ebca00b00191117a414fmr79423463plg.27.1673326722741;
        Mon, 09 Jan 2023 20:58:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673326722; cv=none;
        d=google.com; s=arc-20160816;
        b=AAmgk30MAtYNk/1TkXhBFjfybiVV8imVd6XAIJJ5uHD/iZQ0M3oOy96tGockqWwvDb
         a433w6t7RBv7e3YX66oPaRDMVcPgZ0vowONG1ahn9apK97mFr1V/K2etiuMH43HqZaIr
         Uvw6xZCxCp+wJyixEwbiuUhK71Lz8ziiEu0vzzDwbKHb1IAG8AqBqEGJsd+RaAUtW4MP
         2N0svoj914KQZ9C5zG+UjwRkIzn0mBSce3QkAYlj97J7koyo1PbtnW3epewv399IxqXJ
         LQtrCwRbynm3sgqVw4Vu7OZDzpTr3bGxFGleScX0GkhtIK9VhG73zdLLbkgcxKJFcx10
         Ipew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=2Px0M7YyqlaKTCVUgR/Ohzq0hI9yqWISWDW7GfN+t6o=;
        b=WTDymUzzqTLxJu4dSFZCf4e7VCWes9yp5eU6BuujjEyC9uQRDD0EuMLd8DBadV6y8z
         VairvbgBRjKVsjcXzk6uYh+bEosYEnhwqk/hLqlw5YywtHE+5tO0RUoER3VkPe+upSan
         /lep+lWwOAH4HN8ISMsy3w0Ln+hw3Bh5bfvp4NESWgjMMpk6mEKrUxLGqbiqFvpLS5y7
         ieI+sy3lSbTOyIv1mx3H293gSE3N0i9maL7avimkC1uil/3AS6pn9c4f8JSVwTwSuhSV
         NlsOpF7Y666SO/FxjxNwnzl6CmRUztkP9AqL8K5Jixp8brnp2OzXJ8L4dspxwxOMX7Zz
         gq7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@eskimo.com header.s=default header.b=CzvlkD0w;
       spf=pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) smtp.mailfrom=nanook@eskimo.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=eskimo.com
Received: from mail.eskimo.com (mail.eskimo.com. [204.122.16.14])
        by gmr-mx.google.com with ESMTPS id n8-20020a170903110800b00192c8827033si915229plh.10.2023.01.09.20.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Jan 2023 20:58:42 -0800 (PST)
Received-SPF: pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) client-ip=204.122.16.14;
Received: from [50.251.249.49] (nanook.eskimo.com [50.251.249.49])
	by mail.eskimo.com (Postfix) with ESMTPSA id 439E43C14BF;
	Mon,  9 Jan 2023 20:58:42 -0800 (PST)
Message-ID: <9acae081-9d4d-3dd5-8b2c-52c72592e81c@eskimo.com>
Date: Mon, 9 Jan 2023 20:58:41 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [Bug 216905] New: Kernel won't compile with KASAN
To: Andrew Morton <akpm@linux-foundation.org>
Cc: bugzilla-daemon@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <bug-216905-27@https.bugzilla.kernel.org/>
 <20230109160929.1ecacff5fb8ca2b1ae25141f@linux-foundation.org>
Content-Language: en-US
From: "'Robert Dinse' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230109160929.1ecacff5fb8ca2b1ae25141f@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Virus-Scanned: clamav-milter 0.103.6 at mail.eskimo.com
X-Virus-Status: Clean
X-Original-Sender: nanook@eskimo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@eskimo.com header.s=default header.b=CzvlkD0w;       spf=pass
 (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as
 permitted sender) smtp.mailfrom=nanook@eskimo.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=eskimo.com
X-Original-From: Robert Dinse <nanook@eskimo.com>
Reply-To: Robert Dinse <nanook@eskimo.com>
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


 =C2=A0=C2=A0=C2=A0=C2=A0 Increasing to 2048 did allow kernels to compile w=
ith KASAN=20
enabled.=C2=A0 I am curious why e-mail only?=C2=A0 It would seem bugzilla, =
a=20
public forum would make this fix available to others who may be=20
experiencing the same or related problems.=C2=A0 Interestingly, I could not=
=20
locate the symbol with xconfig, had to hand edit the .config file in=20
deference to the fact that it tells you not to.

On 1/9/23 16:09, Andrew Morton wrote:
> (switched to email.  Please respond via emailed reply-to-all, not via the
> bugzilla web interface).
>
> On Mon, 09 Jan 2023 23:42:40 +0000 bugzilla-daemon@kernel.org wrote:
>
>> https://bugzilla.kernel.org/show_bug.cgi?id=3D216905
>>
>>              Bug ID: 216905
>>             Summary: Kernel won't compile with KASAN
>>             Product: Memory Management
>>             Version: 2.5
>>      Kernel Version: 6.1.4
>>            Hardware: All
>>                  OS: Linux
>>                Tree: Mainline
>>              Status: NEW
>>            Severity: normal
>>            Priority: P1
>>           Component: Other
>>            Assignee: akpm@linux-foundation.org
>>            Reporter: nanook@eskimo.com
>>          Regression: No
>>
>> Created attachment 303563
>>    --> https://bugzilla.kernel.org/attachment.cgi?id=3D303563&action=3De=
dit
>> These are errors when trying to compile KASAN inline
>>
>> Using GCC 12.2, can not compile a kernel with KASAN enabled, either inli=
ne or
>> outline.
>> The hardware is an i7-6700k based home brew machine, Asus motherboard.
>> running Ubuntu 22.10 32GB of RAM but using gcc 12.2 rather than the Ubun=
tu
>> compiler.
> crypto/ecc.c: In function =E2=80=98ecc_point_mult_shamir=E2=80=99:
> crypto/ecc.c:1414:1: warning: the frame size of 1168 bytes is larger than=
 1024 bytes [-Wframe-larger-than=3D]
>   1414 | }
>        | ^
> lib/crypto/curve25519-hacl64.c: In function =E2=80=98ladder_cmult.constpr=
op=E2=80=99:
> lib/crypto/curve25519-hacl64.c:601:1: warning: the frame size of 1376 byt=
es is larger than 1024 bytes [-Wframe-larger-than=3D]
>    601 | }
>        | ^
> lib/zstd/common/entropy_common.c: In function =E2=80=98HUF_readStats=E2=
=80=99:
> lib/zstd/common/entropy_common.c:258:1: warning: the frame size of 1088 b=
ytes is larger than 1024 bytes [-Wframe-larger-than=3D]
>    258 | }
>        | ^
>
> (etcetera)
>
> Increasing CONFIG_FRAME_WARN should fix this.  Try 2048.
>
> Perhaps KASAN could increase it somehow to prevent others from tripping
> over this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9acae081-9d4d-3dd5-8b2c-52c72592e81c%40eskimo.com.
