Return-Path: <kasan-dev+bncBC76RJVVRQPRBMEMS6YAMGQED6A74JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 572A389094A
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 20:34:09 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-430c139c096sf12650481cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 12:34:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711654448; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4EBgqMokZT1Vz3zb2ATQyfoZs1APDiZ3n7hLXUcrPQ+zoEZMaX5c+wgwZqVLyOgHL
         lWF/1nAgFsROGOiwtuJICer1IR4M+FznLUpjdzeJ70NigthSuW53Jo8qtEdic+N3hW5q
         Kc7lyx0Qc0KLuCwsMvCCbwWftPAXwfnKT3vKgYa/wr4hvjSWbP2LknlHDs4+09/z861U
         3TJLxZCRylgea/nE6A26XliHuB7UGiiqF6O5htL3/8klGhZPeKxDJFzHh0jVVcQoN/uJ
         PIrQHYTP3nrWiyfkDjMlRV+xH+Ezj+hFr2jPsM+fBtbqDIa+eqnn4VoEEH333xqfSVZq
         JPPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:to:from:date:sender:dkim-signature;
        bh=Y++5lOBDCIfTFyVxhWhW7+5DLnqxdqsku7Wr9ihmV4Q=;
        fh=cP3XcyDQxP6DnpTfvV2eKyEJviwGDZX+F+lVZzsfr6Q=;
        b=j9sGGjyLPM8F3EfCusdgP03amGgV0BVAKrRjb5JDcLPpdvHID85Vi1WOzwnHdpxhXy
         0yygNeddVHx/fJlJlHvCq2lHa79HqPACVUjov1lfe+m4uj/QGbWMlbJurkl6yMsBXC3h
         qQzjWBQWlMqJQ4vwOPsAq/MilUnwaNHS2omdVZHlCfe0DcYxgI26e0+3thhhCLU5JqBd
         +695cHm0r3rHdBhCaVndSsv9sCFe/HJXQiXUtowe2+1jzTq9oE0lX15x8zyh0ykmGrGB
         clE4+0ygL9gp0hz7MbJO3E477F75K6LqeYYiBBcoMeLnVuSjrUN7wovzJ/HAQGB3zOUv
         K4fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=0q53r0am;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711654448; x=1712259248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y++5lOBDCIfTFyVxhWhW7+5DLnqxdqsku7Wr9ihmV4Q=;
        b=iA6Rx/NiDkJpiwKE6CH9cpOHBBEJ9+qK36gHFi7z9WplMx4J/W54+vFq5IhnMNyyfh
         Rd+0UufCWjK/VM49Ok8pEQxdVH9LxrPmF+4PijqHivRu430Y8KCCNx+s8+BlgxocglwN
         8Gk6anm4QFS9Jn8DmrNAcz0ure7ARR+bbLI0vryYOsl5qqOKr7qx+xdaesBbHFILNmeJ
         nXTtiNv+Ex8O0lK2M/Lwq6YxlwbluWoJHHyTof5xmzH+12l7aUTXH7ItMyzPwWUWWq6s
         h2EWvxRm356lOPu2SlRWhKdq+JgtgIMhA+4QxNSmtB3sZZh3rk+GQGNwOxfFwFdzDQFD
         20gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711654448; x=1712259248;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y++5lOBDCIfTFyVxhWhW7+5DLnqxdqsku7Wr9ihmV4Q=;
        b=S5yEY6+BTgATaodleqSqO8Llt88j32z48NZdWE0h0rXJtCALNyY78W6Rj8Q6NmFtxo
         2gljORPDk7ssdBkp7fL7HgQqn48IQfoBjOYpfBdhqMXCmNdMJmx+vw/qp4HdA3kwqKre
         5QKJyLn2OmeAuj5nWdPBh1/DIdn7STQpakyYgUZI0Vrbrl0nzjVldkVeLI4XMvJTqWCJ
         ccw7TnxBi4ilMWBNMRJYPG/xR/eggI3WOOhAB6NaF0UQvmIOdjtWHrx6gfo1+utO+EDX
         Q6FLrid/CK47tcs5RHHAPz7z7KvnVAO8eQiNc01dtq1M6S/fFC6bJr9dZGyc9bztYpkj
         PdOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTGY2rjr++NTQrIffFI9jFLtIe2bg1IlEu4kn0AKPDHydPDVNMTccXsQIr36T5vgzVeVaxLL1749glfh4iyPyu4pVBJMPGAA==
X-Gm-Message-State: AOJu0YztA77u2PPfdwPEnaHJhU9Sm3t+MDjz7e3sO8H7r9iatYFDBy+8
	1l2fdeczfnSW3aOgkbDtehOlvFLJq5EXvtxVxJyjZrnhRUeYMdSq
X-Google-Smtp-Source: AGHT+IGqqCPzMfjf99a69XkXjp1iUS11O7oOz8pPdQVTmGBKA7Jjp4Rah1RTBL8k3M5Qoo+1QVL14w==
X-Received: by 2002:a05:622a:1a81:b0:431:5109:761f with SMTP id s1-20020a05622a1a8100b004315109761fmr383336qtc.6.1711654448139;
        Thu, 28 Mar 2024 12:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1886:b0:431:1d90:c004 with SMTP id
 v6-20020a05622a188600b004311d90c004ls2081972qtc.1.-pod-prod-02-us; Thu, 28
 Mar 2024 12:34:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2aultk6Bbzmyo9T2NYS6iqSp4eG+PluVzB7gb3BHMvaS9q8U4mqMq1vk3qi5qfvuf9XoNOYEwcQCcEMAJT4BCeSROTizc8WHdlQ==
X-Received: by 2002:a05:620a:4c2:b0:789:ef9e:fa36 with SMTP id 2-20020a05620a04c200b00789ef9efa36mr492499qks.37.1711654447188;
        Thu, 28 Mar 2024 12:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711654447; cv=none;
        d=google.com; s=arc-20160816;
        b=0imX1mwK5HaZbUaCtykXyA4c4WdlDbEdY1sgAKqPGepNRVuPNAyNoUQxElw7GCkShe
         erjulC5ARlL7NEqJuPslNve3bZVLxZ8diaoydCQ7vHAXrTTVIyNtCh+tG9gQ4sMtAwmY
         Cpf8WAn5fzPIkw+bnF8R5BvnBW3ohzxszYYP9vcWg7K5IjJNFaYTMKG8zREFkYckzO/e
         rOObvVUOZmuKDSEPEV+yLhVSrwf4toJ6xPe06Nr6LcHCuHeqJd8csuGC8E+7n9r9J6z5
         Qf5vvbYZWhdL+/5bOAareNJD7Ug8JpzC/U+TtFS2v7eiBeBZ4GGycG/DJyCDIHc7mjkH
         UQ2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:to:from:date
         :dkim-signature;
        bh=XFkewoBSuuA+NyCvB5QMwy0Z4HM+U6hdKrpuaoxhXDE=;
        fh=cWi9yqynllZKt7dhQLHLkV9ZW5Ux/l37sI9hbYh91AI=;
        b=MODOp1/W63XS1IohKe2ypxxgO2iN+AClzaTya5YIE2vpKb5iusDaPVF6tWeAvplEm3
         8hiiJEc6N4N2c5AeFzTwIiN2mmSJZQUCs34Gc98IX5gZvaJuXbxgZZKGPTFcB3u6517f
         tOKeUuV4oFsCkIka6fa4/lv82lWf1irleNjUE0EzFaqITmR1gdsc3ZzfhoC017LRkVB7
         0vYYO7FTttHOjbG3wQI/wb7JRwgoDQJtW7HLVq2064kai2jeuTGnYyle7zlpSgiVv6Q/
         qUeLl1Ogo32DwcGZDgXSU8zhEhscjoP9yqCsKj7yaboMEbRJ5M0nas2rQUXZKVoKxFL8
         BzBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=0q53r0am;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id rv10-20020a05620a688a00b007888f466670si150374qkn.2.2024.03.28.12.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Mar 2024 12:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1e0025ef1efso10292765ad.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Mar 2024 12:34:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVV10PhxLmTeAwB0O/XJiflkeLHDO+tJEKO/Dcv3/MNjW2/3VMdsEiJjuxQFEmmnNlG0ubWmccclsmG0GKMOxJ7NMAAFtjsCD3gQg==
X-Received: by 2002:a17:902:a388:b0:1dd:b3ef:4528 with SMTP id x8-20020a170902a38800b001ddb3ef4528mr429956pla.52.1711654446258;
        Thu, 28 Mar 2024 12:34:06 -0700 (PDT)
Received: from debug.ba.rivosinc.com ([64.71.180.162])
        by smtp.gmail.com with ESMTPSA id o8-20020a170902d4c800b001e0b76bcfa5sm1995555plg.54.2024.03.28.12.34.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Mar 2024 12:34:05 -0700 (PDT)
Date: Thu, 28 Mar 2024 12:34:03 -0700
From: Deepak Gupta <debug@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Andrew Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>,
	Heiko Stuebner <heiko@sntech.de>,
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Message-ID: <ZgXGKxp0KAQI/+NC@debug.ba.rivosinc.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
 <17C0CB122DBB0EAE.6770@lists.riscv.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <17C0CB122DBB0EAE.6770@lists.riscv.org>
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=0q53r0am;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Wed, Mar 27, 2024 at 06:58:45PM -0700, Deepak Gupta via lists.riscv.org =
wrote:
>On Tue, Mar 19, 2024 at 7:21=E2=80=AFPM Samuel Holland
><samuel.holland@sifive.com> wrote:
>>
>> >         else
>> >                 regs->status |=3D SR_UXL_64;
>> >  #endif
>> > +       current->thread_info.envcfg =3D ENVCFG_BASE;
>> >  }
>> >
>> > And instead of context switching in `_switch_to`,
>> > In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR=
.
>>
>> The immediate reason is that writing envcfg in ret_from_exception() adds=
 cycles
>> to every IRQ and system call exit, even though most of them will not cha=
nge the
>> envcfg value. This is especially the case when returning from an IRQ/exc=
eption
>> back to S-mode, since envcfg has zero effect there.
>>
>
>A quick observation:
>So I tried this on my setup. When I put `senvcfg` writes in
>`__switch_to ` path, qemu suddenly
>just tanks and takes a lot of time to boot up as opposed to when
>`senvcfg` was in trap return path.
>In my case entire userspace (all processes) have cfi enabled for them
>via `senvcfg` and it gets
>context switched. Not sure it's specific to my setup. I don't think it
>should be an issue on actual
>hardware.
>
>Still debugging why it slows down my qemu drastically when same writes
>to same CSR
>are moved from `ret_from_exception` to `switch_to`

Nevermind and sorry for the bother. An issue on my setup.

>
>
>-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-
>Links: You receive all messages sent to this group.
>View/Reply Online (#680): https://lists.riscv.org/g/tech-j-ext/message/680
>Mute This Topic: https://lists.riscv.org/mt/105033914/7300952
>Group Owner: tech-j-ext+owner@lists.riscv.org
>Unsubscribe: https://lists.riscv.org/g/tech-j-ext/unsub [debug@rivosinc.co=
m]
>-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZgXGKxp0KAQI/%2BNC%40debug.ba.rivosinc.com.
