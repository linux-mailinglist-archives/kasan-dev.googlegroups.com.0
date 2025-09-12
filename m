Return-Path: <kasan-dev+bncBD53XBUFWQDBBMFNR7DAMGQENGWVG7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 763ADB544E6
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 10:15:46 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-31d8898b6f3sf2572793fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 01:15:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757664945; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sm4htpWbLJ6z6dEBabBRwwNy2n0v04q6OFM31vaeArl1RktwJ5VKp861ZRqO6OyVe5
         M6aDu6qsXVtl0Z0TXUW/rb81XLYKYYGuDxmGTiofLtqAz4eqmkgLl7pXLGrGPYC5buMo
         4nNNdxY5DC2CudeR5H9hvIJePupOXp50dB5ZiJRIlg2CatqxMkKf00ROVwM2OWpQvd/V
         4w1VgknCvuF9xNPY1lrgqgS3kvneQ5bkTcJ31q3C9lXQR8jK9vXmz4eO1be+pLoA/ovT
         +V0CS+fs+bqXMvJRRG3oosQC+yLd17pXvxYw54bkf3DzbsUMIZlFudwAe2DJY2gzfccG
         78Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=mke0+TtU/0sZ8Upr3pt8V89wfTnNy+Zn2CSo94YeOHc=;
        fh=AvzwiBxpnRKhOKmwBcOp71RJWxbyj2oZeS3HqsMgZ8E=;
        b=dMcs9kQgTRo14iuhpRu+dy5TZN1EaUTpXqxyBvcpFfcR5wTilZF4+66aG5eQfRddtY
         +u3pVb10ZNAXpHHaSdKYVMSlG8H8of6VSzPdiI7e14qecAocsyFlLf+g9/3dhwhZpryL
         Q8ct6BVzcToe8mcX5AFp9qXYXBevEPDDvtfTmLQLmHIBEVuZI19rDOAOgd5oh4wEvC8g
         keLrpONyqkqtNLJX6+YcV6LjuoFWWd+jXlSYoWPA7FAeNlGDYmstFsBxi3VX4b7Yd+2z
         DLmFCGqXkdIL+49Vm7zbA1TFBrTJ9OLR8OSa7kC5GTN8sHVZ9h6MPKf2oZMTT0Yk4kyP
         n85g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EKChy69Q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757664945; x=1758269745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mke0+TtU/0sZ8Upr3pt8V89wfTnNy+Zn2CSo94YeOHc=;
        b=RLGdBC/y2QpJRfX2bD0LzBLldpT9rlomc1aDSWrgBi9g9apGiAecibJYhGm2dhtvtA
         UBdyodMsXCXVPF5xcz+59lAb3Yyfpj5qSL9nxmHypplSJVEMqQsyD3A9fC8GOasWzZUr
         N6aLj/p8mg35Khx+TD5jNpelNJ9NyxkzVUTtb+sWiZjAyg1l3FqX2Xq0rVH0RkSscU40
         vyDD04DJNkCGD8Ik/6H1IAquolJxVmWPc87c4jSGee/2CquelNErzTs+AyiEJztjbBBE
         JxQgX+7QH+HwWkJj1JOgkmVfeZCJde1WcL0UZPhNDLkG0AuZOYGav8uYVdeHuId95cmz
         TqVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757664945; x=1758269745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=mke0+TtU/0sZ8Upr3pt8V89wfTnNy+Zn2CSo94YeOHc=;
        b=KwIpXzP/YTpEuu4/cRLoO5TD8Om6O06WwIyg8gtTp260Eoj+eA/o/0mZ/npDjskYsm
         WiyTIj9GmiVhF6AMwLqS8OIfx7CHmLS9mEgO5X31fNtzCTBEJDnti8wMbmwdjF2sfYb8
         ShTN+RLAp5KI5dE0c0qvVGsdfQqz6a8TZE7RBjJ3zYXaIDMDzR1/4D//Gboc+w6PTUmY
         Tb45gFMCmx/5wLcr38BnEg/N7RsZDUWE0+P0Ydq5zLLNYK52LcFExW3Olfpaz7C7DdQI
         bDdF6Ye7xBmSOyz2+OexARajvI+9SbtxKYU0+JSqBGY9VtQxUvDU5gEUpl7lWjX6oIci
         EkTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757664945; x=1758269745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mke0+TtU/0sZ8Upr3pt8V89wfTnNy+Zn2CSo94YeOHc=;
        b=OrdYwynTHMMCPs28Gbyz9nyiTlEGKcAO0hVUIU/86DBNycXDK5cP6/09QZyZtYnGeK
         JhxvAwRjic1o+9Nl8wBWcQkVRQsmNTwGnlRRENl90a2b4iekH4DH91pICRyVdmkhqBE/
         xa8Y88EdGsPONExA9LqC7+F6eRS2+V4H8icMOFeZ4PcGecTpu4l8QD5bB8OEbHgxWsOE
         Eh/ukgJdxSloVTweyvQLmsY1WAmGvz94ltPJ8MNyBkX9ZianwXfgQ9mpX5AvhzcaUH7V
         JoxdztzHqU9SJksnaUM852FQ9eRy3T/9eOChhe4b5M7t2e2a/i6/UYp8Qdh17oQ6lmK2
         FqEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAw8VzrI5y0PHNVyIuHmaUa29dm3m90BwioLovqY6rMMfFwbyEGBY6wxcEh3WOJsosvB22ew==@lfdr.de
X-Gm-Message-State: AOJu0Yx14Zto9dqGjZORwUmkveLlMjnHJ0Pwp3cDdUA1bgMWooZEicGD
	XAwS3Dx2kLcoDKfiUMyyLQUhudvkGiAY9F4GrF1j3xYEBPbgEONpaojJ
X-Google-Smtp-Source: AGHT+IGzdCl6HutyLuO6W90WSzzjz28kMssqteXDxMFykn5J1e3XonUe8I86QVClDv7nzC+J57THKA==
X-Received: by 2002:a05:6870:bac6:b0:301:2bc7:61e7 with SMTP id 586e51a60fabf-32e572ed9f9mr1222741fac.26.1757664945093;
        Fri, 12 Sep 2025 01:15:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwXu5+N/7KM0lxHWrQGuzZej0DwqD/IQ0t+V3oHiEvHw==
Received: by 2002:a05:6871:6201:b0:315:8af6:e4ed with SMTP id
 586e51a60fabf-32d0682bb8cls1237009fac.2.-pod-prod-05-us; Fri, 12 Sep 2025
 01:15:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbLysegq/WCbh7Y+mxlTeh+EdRdWLbvXqS/xY3MJ+lC8JwNa2NPUBCbedvZfxCBJPsLJCvPesQMcM=@googlegroups.com
X-Received: by 2002:a05:6808:e83:b0:435:728d:ed15 with SMTP id 5614622812f47-43b8da38402mr898513b6e.38.1757664944209;
        Fri, 12 Sep 2025 01:15:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757664944; cv=none;
        d=google.com; s=arc-20240605;
        b=WkRBzpMnh5G0mMxebSEjEI2oeA4BVHTyFOhVMdZ6ufwO20iDuCj4jZWQ+6QXkenJ9H
         /GCk7PBjIW1mI6sFa5DDyQWJX5SgCQOeZI8jZBEZTajs0vHTh6TgIqQ1uxN+evE8oKeR
         RgW/yLunlw4xTv+v6ABefz7vOrErMZ6ewRSav2LDEG57eoX9g5gRg6nW/i48c51sB7st
         zhTMX0X0Z5tSqSi8Ga/aciVJ3v6b/4d+jjEIfetHqQxgo7f2OdhJuaM5xLmgPbh2REzI
         yGNXhzptUDZKiv1dFmAAzwbl8nzCfM90BWWMyonlM9NYxSyCWKV3Ndf8ddEUIsPNtVVE
         n+rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=b2EuFHC5+5B8ohKz2yz145rUlrp5xKfqVTKvvn+wKTM=;
        fh=EJVRchjWPXr+78DLxqHdlCbMm2iDXdBCZ/AdGox3fos=;
        b=iLYPa1c7vcHjy3g4YnJ3sBUt28aV0QGHB98rIvHhoQE5KNK5DGiN9B3dqICSpnnrP/
         oSN2HW1biYZwwOQ+9x/uf0slS5UaV/vLMvzHY2S061g3nbBm3Y+BRbD6RrrnaQQ9CZ+u
         0IYt2Bmp6RBkOs2BPmgg+wZQ5dJnocdB7NV3RmK5xHfICEZ/7ti2UeNF3AGcNGTxnXVX
         uFjpE/9iP1ffeUhqp/AjnJkETUA73e+9dyDSb1GUgu3HEGmyAP08oDWXP585reXJtR9L
         ejKzsg7JH4zsoOR8Op5y9SA7jJdmd33/B8N0kSQY7+Vwz+yWTTjQgYdLrcAI2KyKJYXM
         GpUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EKChy69Q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b8dd21b7bsi56572b6e.4.2025.09.12.01.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 01:15:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-b4c9a6d3fc7so1012967a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 01:15:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOP171KZaoqMGv+LSRV02dPOYwi3x0KW5nqqlLRSBoR9lT7C5zlqAZoW4OOS2ebV85ItEnZ6FM3rU=@googlegroups.com
X-Gm-Gg: ASbGncuergN3GGh34OnrNBJz8Zjtwzh0MXYLaCmKhKizIaeHKm7NuP9LM2Mbl8rgaiz
	/1tb7lVVZ6FLgb2q5KJTNFjsGcXL+QO8Ua8f0zmV1FDZLkMQXUvIfse9HZ+AVo28NEmtdGCYFvP
	BEGEZpmwVW7HiriDHCNBQpkZb1b7rmyJD6VmQEU1IhIXKKJnteqgSt8KqdBTEJhjh6TlghdmT9p
	sKjaYpF2VEgjwdH2uH08Kumr3PfdFmeFsLhgptqrBhei7QdhNJORAFRpTWlMmPNDHYQ9DYpXWkL
	LFQUg07IUBG3kruMEh9Nbqc63B7AsyozNkW+IES2eT1rqUIS8hj7cgtOE+uO9rev+sSlzqvQlVa
	M6jf8okk86vYerlMX6A==
X-Received: by 2002:a17:902:f707:b0:25e:78db:4a0d with SMTP id d9443c01a7336-25e78db4d35mr3480525ad.36.1757664943639;
        Fri, 12 Sep 2025 01:15:43 -0700 (PDT)
Received: from [127.0.0.1] ([2403:2c80:6::3079])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c36cc580csm41503445ad.10.2025.09.12.01.15.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 01:15:43 -0700 (PDT)
Message-ID: <8c047b5f-f4c2-4795-8ceb-a556ac6647b2@gmail.com>
Date: Fri, 12 Sep 2025 16:15:30 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/19] mm/ksw: Introduce real-time Kernel Stack Watch
 debugging tool
Content-Language: en-CA
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>,
 "Naveen N . Rao" <naveen@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "David S. Miller" <davem@davemloft.net>, Steven Rostedt
 <rostedt@goodmis.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>,
 Namhyung Kim <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
 Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>,
 Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <aMO07xMDpDdDc1zm@mdev>
 <CAG_fn=V5LUhQQeCo9cNBKX1ys3OivB49TuSeWoPN-MPT=YTG6g@mail.gmail.com>
From: Jinchao Wang <wangjinchao600@gmail.com>
In-Reply-To: <CAG_fn=V5LUhQQeCo9cNBKX1ys3OivB49TuSeWoPN-MPT=YTG6g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EKChy69Q;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On 9/12/25 14:41, Alexander Potapenko wrote:
> On Fri, Sep 12, 2025 at 7:51=E2=80=AFAM Jinchao Wang <wangjinchao600@gmai=
l.com> wrote:
>>
>> FYI: The current patchset contains lockdep issues due to the kprobe hand=
ler
>> running in NMI context. Please do not spend time reviewing this version.
>> Thanks.
>> --
>> Jinchao
>=20
> Hi Jinchao,
>=20
> In the next version, could you please elaborate more on the user
> workflow of this tool?
> It occurs to me that in order to detect the corruption the user has to
> know precisely in which function the corruption is happening, which is
> usually the hardest part.
>=20

Hi Alexander,

Thank you for the question. I agree with your observation about the
challenge of detecting stack corruption.

Stack corruption debugging typically involves three steps:
  1. Detect the corruption
  2. Find the root cause
  3. Fix the issue

Your question addresses step 1, which is indeed a challenging
part. Currently, we have several approaches for detection:

- Compile with CONFIG_STACKPROTECTOR_STRONG to add stack canaries
   and trigger __stack_chk_fail() on corruption
- Manual detection when local variables are unexpectedly modified
   (though this is quite difficult in practice)

However, KStackWatch is specifically designed for step 2 rather than
step 1. Let me illustrate with a complex scenario:

In one actual case, the corruption path was:
- A calls B (the buggy function) through N1 call levels
- B stores its stack variable L1's address in P (through a global
   variable or queue or list...)
- C (the victim) called by A through N2 levels, unexpectedly has a
   canary or local variable L2 with the overlapping address with L1
- D uses P in a separate task (N3 call levels deep), which modifies
   the value of L1, and L2 is corrupted
- C finds the corruption

The only clue might be identifying function D first, which then leads
us to B through P.

Key advantages of KStackWatch:
  - Lightweight overhead that doesn't reduce reproduction probability
  - Real-time capability to identify corruption exactly when it happens
  - Precise location tracking of where corruptions occur

KStackWatch helps identify function D directly, bypassing the complex
call chains (N1, N2, N3) and intermediate functions. Once we locate D,
we can trace back through the corruption path and resolve the issue.

Does this clarify the tool's intended workflow?

--=20
Jinchao

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
c047b5f-f4c2-4795-8ceb-a556ac6647b2%40gmail.com.
