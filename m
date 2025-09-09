Return-Path: <kasan-dev+bncBDW2JDUY5AORBRX3QDDAMGQE656LYXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 679DCB4FFDF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 16:46:43 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-629f069572esf2276940a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 07:46:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757429192; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dcwq1V/QLLB72XTJPC6bofq7XBYkZo+K/EGbTRS/B+v+hoPs2kN+Ig/VMGVESY2d7m
         5JhYWGhDV6q2fvkHQzKxvZlJJ3fyyRPTIf5NuKutWfd4+++rzC/HLXRvuZgaSpm32BGS
         xo7cpS89YRM12dkVIHJPo3cXRDld7nLgV5DxgJn3iqt4czraJHlKhc6e6EML4Ytj7/Xl
         EDLw20b2fck+lJtI9e0LXdgWaHapbo6wA2UVQOxj88dkYjv7HOUbpOzTc18WU1OsnCpR
         nTNvLbFO5DjOeRo169UAuvlPsyD9VunMbbImC5+fHJeGfkbKtQQL7QlqoS9yu6OEZf/J
         vBqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=cCL63ufaoFRTnViAYq9b5vWapsAEt7pZm+m1TjY95IQ=;
        fh=+uXqRSqKtJkzA95VyWo0cmR3DFIPQW9bVWFTGA320Gw=;
        b=WXRMlkyLDnBSAOmKkM3DfTnUxNCzgswMS7YGUG9TCFcH/wbZGxZe0lLbStrcgLiCgY
         9wggqmCYKi5vAjwjO+BSLxpyY3sOpU4hzVnWrnvz4g80HqDjW/EQ3ChmyuEyFAZE7HTb
         V9HSlvTnQVz77KIRik5jmtJZF6Vr3jl/64EUM8DbooOgOniz889qigYBYNXVNQeepggZ
         KcjrqSq5YruRTRoJLKPn1gKzoPmcpI5O4PNOzUsC5HDCA4Ppe5XZPvEHhvklNc1FECC1
         CUo09YiO+jGrBcqCPBd3GLCr3srqmrIQ+ZxQST3sW+nIj6xgwNvpiUEmOR2816maxxCV
         dSNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UJMLbUkQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757429192; x=1758033992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cCL63ufaoFRTnViAYq9b5vWapsAEt7pZm+m1TjY95IQ=;
        b=B3xKfgP4lu6myOgHc0oAOGzWuNgM0JhSaLjkRPSZgP/qBel/9yNN1xBePksuPiUZm7
         yssbzKYPf7kKyH5bZ/elzEQhcaLqINAUAuZuyWNK+tm4D9TBwsT8uYKS/HYwUadOJF35
         WmUVbljjhKemsJhhC0PXvF4ZyoC9OkJnEZQ7nz3fy6QWszbP//ExW8ATsu5xXfMo4rZ6
         7X6IVLKDj666n7BnT553OWfvIvRmUuqC3MU3lYHL+MUIP92ALgaqvhIte5ApSM4E8OKN
         drYaC7EmwPb0/o8V0LJY33kfzPPqp9I9GxNzoxmtBqp8ZNpNrLkSeB4adyXMYl5okQID
         OeYg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757429192; x=1758033992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cCL63ufaoFRTnViAYq9b5vWapsAEt7pZm+m1TjY95IQ=;
        b=KVHs0MeWi6laG1kTNFaHFNbSnDUvwGKNNtxNtprALOOvMvAvb/OjmNpxu1IgOniXo5
         vJQeNIkwSmW4BphN6PWVRzO8V03kAJRwjaTZUsn07+8CE1WGwHHObhpXSYNCkNhNszCK
         JjqWE4cbJXWx9cpZ4EfvcRI2ur5GCfmhEImrPL07Y7MrKQCPiIEL96Tehg3unrQLqf3O
         KDHBoq+Qit3HAmSNkGHgvBllHpgj9uRofAmU70FJ4ulXQUvkivzl1JbCuk3K8+XnMzOg
         oM89Ei1jE5q4DcNwqUsHnMVeyPpeARbjTlQfkaEOkcVRpruoMLibuv+vc1isniyRUEnV
         LMgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757429192; x=1758033992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cCL63ufaoFRTnViAYq9b5vWapsAEt7pZm+m1TjY95IQ=;
        b=QpjyFA7wRc0y0pXk9+MjttLPeF5vjg6cCIMzEZ6CH063XY9NqXYTX8+Qa86t2mwbFr
         /AAiinGFlR4LvR7sUj4lh+aNxYirXOSVAMFEbx60jMnoI+E3dv+xuTCcANg2GMXKYZKC
         g/e2sdkwp+UZre1/qCLZ4E6c1xOL22CP22qPkSzQ4n/K76Cq5w5LIowEJaPf3EtE3Vav
         O1TMxQbNJ5M4wWWM58fcV8l3RUrhijDkyjTmktXpcxUYzZMSihHTXfEtH5Rlp7qjWMZE
         ClUyskNPwRnP6o/U8Voqh1cPStkeW21szd2Ss7PDXxSiq4GcRMm/C6BFWn/IT2I8ou/i
         1/OA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUstEBcW1sqv56CcFzCkUOGlDWXbdojgFQmp1K2lV2F/I/G4iwx/YxGKgolXR+XkCX9xJyClw==@lfdr.de
X-Gm-Message-State: AOJu0YywT2sfbHOoGs5nIyrIBllJk4Jd7d3T4zhP5pD3pTNHhJryeSKt
	qGHoZ9w8Wi28JOoZD5Gcv0Pq4H4oxnvpWBgjwk44mWOYMCk78c/lX3gX
X-Google-Smtp-Source: AGHT+IFfm+k0JNuXIUjQxrR46Ob3bubLtI6dSgPIzRByNzOorzwE0+Bd6N43K9NDlzcaqVFJpeenzg==
X-Received: by 2002:a05:6402:d0b:b0:61f:eb87:fde7 with SMTP id 4fb4d7f45d1cf-623ebc4491emr10956170a12.17.1757429191326;
        Tue, 09 Sep 2025 07:46:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4uvKezgp4JRHEgFcx8m2Q9y3uUbzHUlt08fFEYUCvYog==
Received: by 2002:aa7:c54d:0:b0:62a:bd63:ca1c with SMTP id 4fb4d7f45d1cf-62abd63cda4ls803101a12.0.-pod-prod-00-eu-canary;
 Tue, 09 Sep 2025 07:46:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVT21NAxBJPwxntcN95yfA/rWbRCsXa7qVURWL2LzQd40hp+H6O2UiTl06GYgRoFj/mtASCZiAWHpI=@googlegroups.com
X-Received: by 2002:a17:907:805:b0:afe:94d7:7283 with SMTP id a640c23a62f3a-b04932a2452mr1724358666b.32.1757429188744;
        Tue, 09 Sep 2025 07:46:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757429188; cv=none;
        d=google.com; s=arc-20240605;
        b=ds3cqvUG1/i58dNOlG/VziXb/5p6ymlKKr5FN11ZmWNfIAzeK7GobjkvvDVRsvfgAN
         giO4v3wjz+QPGBQOwry2ZG0VcbwsTjzSKLQDALaeT1O2UCpBKq7Sxw0qn9Pp6xZl8BpG
         C30/d7hrqptQuyIBbsIkZSQ2v3RUQu/JZX7AvQqcayVsqAz6P4XvxmoMU7arDvheH5Oj
         aqOLC+Vkh4XHyWtOf2yBJBtmEObEoI8QJ/LATK9a+PvtkrQ1IlO3YEMJsoNuWcWVVLCM
         cjSZcbYEEz7hCjQdts1QhdlC1aio2RCx2FBeFEaiP9yeFmsH1zqHKc+83rMcU9WOATxG
         28KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9r8is19th/mpc8+gBUPuFGFOMpuM+eINAVaHU5/+AZQ=;
        fh=pNgzxXC9wkBWAQRkbJK1pp/9NgjN21sovmtHESbP53k=;
        b=dm2GrZJH19bTt94oq4Te0kdg5KWlDBLX0C26MLzLyQ0MuLQCg30w9N92+D+7chT8MV
         RK280C2d+v0opI8i/z4oSZ6oKflg+jzu63/N/35PhmBcIPCdaXUoFuNqVzrI9QUDApDa
         pHWVXovhZhBt2LHDdZaSeCvU4ZzhZg7aDmUt6+l4Sb2G+fBOD7FGv9UtacR6JDQDiXyM
         gxtjjVbpxs/obadBl/8kleNhByLhNRB2Xoue9+c+fhE/QDWP+CfnlslFh1NarSOT2Tu6
         MTAnWWvai1O3eaqFSmV4bZwXC8bTh1U1rQLoAEBiy5sH/s2cGvvAeaW4z1OT89c1MWsD
         cGZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UJMLbUkQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aff04cdab8csi57905666b.1.2025.09.09.07.46.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 07:46:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-45dd7b15a64so38304155e9.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 07:46:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVmrA8ykJpcrtybvyBejbxjD1/9BoPzoDGNSzuPY5tgRPBkXckhN53VJhN9rbrvhorx+9FmCIQg78k=@googlegroups.com
X-Gm-Gg: ASbGncvINJGasCrfdjkgoD3Qqkr7VQlpWqw7xk/r35pJv8vR6ST+QqwHdAINwSK6KkW
	Z+tuWcw9lKkbjs74RvdVOTR2ha59DwR3el+KIiZQLd2yXaO4P9Hc1GbGVXnQqX023gW56w3hE+3
	P2c5I9kwRo8L5olbVoMHoeBaFIZuDUYnl3BD216QeystwcqhTWZPRXfHWeWYK5JpB3hqyK3Tghg
	o5PH2FNCAUBMmVOU+0=
X-Received: by 2002:a05:600c:3b1d:b0:45b:8ac2:9761 with SMTP id
 5b1f17b1804b1-45dde20e5c0mr116112155e9.13.1757429188072; Tue, 09 Sep 2025
 07:46:28 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb> <47ip2q7fc3q2igjjjg24bl3gwlpcr5y37pahkqb63ridzj262u@augjvsnpq4kz>
In-Reply-To: <47ip2q7fc3q2igjjjg24bl3gwlpcr5y37pahkqb63ridzj262u@augjvsnpq4kz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Sep 2025 16:46:15 +0200
X-Gm-Features: AS18NWBnjU96S1X9HzwLOYnj48ud-1aT029AYj3EOfOXKk4tlcXWbWhwT0m09CU
Message-ID: <CA+fCnZcG4Eqy84zNuvZ2Tumi=eA=KAGFFeduRLiUUHYRBMuDqQ@mail.gmail.com>
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UJMLbUkQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
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

On Tue, Sep 9, 2025 at 10:54=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> But as Peter Zijlstra noticed, x86 already uses the #UD instruction simil=
arly to
> BRK on arm64. So I think I'll use this one here, and then change INT3 to =
UD in
> the LLVM patch.

Sound good, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcG4Eqy84zNuvZ2Tumi%3DeA%3DKAGFFeduRLiUUHYRBMuDqQ%40mail.gmail.com.
