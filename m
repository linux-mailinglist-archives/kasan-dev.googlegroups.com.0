Return-Path: <kasan-dev+bncBDW2JDUY5AORBGUS667AMGQEITK25SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B4FDCA6C405
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 21:16:28 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-438e180821asf11326665e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 13:16:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742588188; cv=pass;
        d=google.com; s=arc-20240605;
        b=LG8NHMOaGl0KVAj6RNOKsJJcI274I2abmjtwCqkaTGmjoRu7XGMFTlye2KPCHMfqBE
         1oxpowxU/vcpoTdDxojudYy05lXEeIHNCMpFNjZZgE0Mn9zbYwfpH8gb0Mg2h+zX9vql
         lZSo3290S7uRqNwVrblANqTRpgReIJU0M4FiX87xajuIrlSKDGQUTOABff85MMO3I9d8
         duex143AgAKkpJBWlJVvGeLfgCdUBVnHkZT45wPkJL3lyTHx/TVtv9cDggdJ92yFsPw8
         0Gf+UO9mEwGWDYEivU6BJDiBy58M4od/5mQZZvGEhndvN8jtLZ6Kk29bpiuubqaarZB5
         ZzlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LH71wk50po36JmpBXAlnDhccn2dLtgIvjPhgrIzdFe8=;
        fh=adKH+aqTzavgLaxitDRe6YYEeTHr3qt9NWLwa5W2v9Y=;
        b=LKDIlPZTbzt8BGVqxy5reuXltHNWpBpyO6p0WcJN+zmIKY9jFNmLoTyorbJxTAV9/b
         IZnoW1iOdQYdpZ3h52QsqxBgdQswQto4NbitUsfB0g0ZWXCXXsJcIwNhPuDc7yrFG4hU
         fG+MTzIhXjqHJVW1XwvttGjDvykFRRNPfBStklFWwxCDC3qtoBd/KwdfvYmxAXuhWwC2
         5/pkFduIkVzcb/pQtl+GM7hLvzLzB6GyDCITFvPprbXSWZn3YbZBfUe5BXqj1kj3Klsx
         6KuduqTMos9anUuB7xc/SBjZ7alNbAdsbL0Uf3mBQQ53dV0hShkUIG/T9+hRcMeUIqP1
         HSKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hOJolEno;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742588188; x=1743192988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LH71wk50po36JmpBXAlnDhccn2dLtgIvjPhgrIzdFe8=;
        b=nP2NcW3BpcBse3GrCdzUsJ4CWKkLEW8aQk6PmJLJ4KavLwdGm2X4QA9u9P3qzcq23W
         PWrz9pBQ8QCnF2MUDnjRV7NhMzFoD8CzyAFcYxpJ30dpHKQ0S7GjTIeZh66YabPJBG2I
         qcUgItyCthEtOyeDou6eimH8AwVqt1NqGpPn0iySRYa4zzUGUH84O2dCntTw3mqdbyqo
         dNY1ug7MjeUOiDpApm4lEYEdTE5g+SSzZ7iUaDY48NCMwjgTNpBHCioUpXW3389I4Jr5
         cL66aJhGrduti9t0A3L9Spomq/57lGp/+7UwE661bVbIAV8Je/FI2MlAigoek0k/Bq57
         9sug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742588188; x=1743192988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LH71wk50po36JmpBXAlnDhccn2dLtgIvjPhgrIzdFe8=;
        b=a8UudT6bGdcRE6Q6xYE2fqFkgazI67uqBYV+XZTsG7kqEMCgFIT9km4iIvUDK7QgBd
         phZ9GgDs2DwDQKMWcs+g3/GQ5CVQi9tn8TOkulGFzejFAYKlxPQl+VUjDux8YQUGCQiq
         nHsoD1GlMeCv4TYcq+iM+RvcUG49jnv8ZI9flHELb3hVl4+ucgeZiGQBwBk94guE8rKn
         Jw2+ZNx68wFeQI/fIKliYjyqA2fxL/KCUWf4MzHJBDSnIljYkT9Mpffk7TOoObZ4CgQc
         rTlYiLSlys4o6rgoE2fa7/vzeCb/d4Wvu+m520i68dn/szrZB77kbR93lUC8tMXJyYwc
         pbGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742588188; x=1743192988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LH71wk50po36JmpBXAlnDhccn2dLtgIvjPhgrIzdFe8=;
        b=GtlJWNRdXqaTuOZgv8h+P5cwFSuwN96e7gGg5vsQ8SNdGp6tIMV+HTB9BKPlep+DnX
         ACnjzntJF7qC4VkUlw7jSVM+KuHRFU2DHKzztCwiFwIC8uyt1iwuL+iFD7DuHafS7s5z
         T8cSMwvP1r1pZtG2DgYl8KkwfoVcKWOnIW5AfgcUunK294LsWiV6qsmnXUpSuk/wdr85
         SVv+xcDGeIhsEXVjWrNWApj7ieGRfK+OehqBSTPmdlLeSlhlUfv9194CGB2ijIY/bFBy
         W6+delQf4EY5UrWDF8xh5j5iGG7yZ6nXqdKk4McTTf+mKhSsUTUxFI4/skfyyH5jixsP
         GrwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmj/U5BHEx6utWRQa/eXEjxlgmtM3yra0zAMmGsWUaaYbzsb0E0cDxNTtLbJ8vkN3iKzHe7Q==@lfdr.de
X-Gm-Message-State: AOJu0YxhFdj2OBO449UdH8ImQNiTioyregQitOumjRFqkgkXb5AF4KFq
	lQPNWQRtvvZX10IQXJ/FBIQCpsXMd1m603tvIQsdQNvU8IY4oI+H
X-Google-Smtp-Source: AGHT+IGB7kiHbZv6IefYX9bfzJqXDZbCGvfdCZTrNs37O1U59JIPNVQDt9SvsvAvLBEgzt8P93fPtw==
X-Received: by 2002:a5d:64c8:0:b0:390:d6ab:6c49 with SMTP id ffacd0b85a97d-3997f94d923mr5157733f8f.35.1742588187337;
        Fri, 21 Mar 2025 13:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIDomqE0/KA5Zr4lO4BJpW2F6Op6RixP6NKy9QPzXzzrg==
Received: by 2002:adf:e701:0:b0:391:255f:e1fd with SMTP id ffacd0b85a97d-3997970ae87ls226280f8f.2.-pod-prod-04-eu;
 Fri, 21 Mar 2025 13:16:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGBik6RPW8IJx+aNhra39vUkOeqZm2pl0+jMvPHZtAFWyieFh+hzzvvK/kfHqL0Z22vC0PHfmscrs=@googlegroups.com
X-Received: by 2002:a5d:47a2:0:b0:390:f6aa:4e77 with SMTP id ffacd0b85a97d-3997f90ff68mr4461982f8f.15.1742588184706;
        Fri, 21 Mar 2025 13:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742588184; cv=none;
        d=google.com; s=arc-20240605;
        b=gcGjZW7LQL4zxFUbWSx3bk6pIjF6BS2Pd2cCtO8Pgu09MG+NApEnPFfoG+NUYhtkKA
         cx5y2gnxwMaDrQLG6bSkgvGQpllkji20KVT0LlpKgHJok2qRvJ7ithA/MrE3VH65ekIz
         gGpVNwKF3ZedJFlazPHv07VbhdxSwua071Rfn7Wbg9ZDAExEM6VdsSSZl9mRu+fbOdQ6
         9PG8WJp+UxYyTIMj0EuGLfdtrjvyLOhSNcx9eXGJcxz6vU2MbABtlmLo1uIEhJXjW6Mh
         49UngTlJrMLG/wb3W+a2kIwXS5MHat5IKBlvigceeJDg64FRJvVGj+4RmjHRdnsHwA6z
         qPMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=C0+RouyfLpsQW5xvPju9cRpnBiU/H1OG+89X01tDYOY=;
        fh=ia+bPwy/h9/Y3p03MUL9/pEbANgFoKTONfD+u/MrEWc=;
        b=VjKG5K85lDXQoKs6FWnEkEBu5n7wpmg7qaXpF87Xzbz7q4TNK/cXYEGD+xa+xuE6I+
         346EeDwrSusmzMTgL5hiv/gQ2qWlJ/8+eBhL2MVEqhrRHwkzlMp0E0A7GGUiy4JGQi3I
         NUXrWDlbtGRUXRGTYkaD5yWXvsZJWFDU0YHdSdPSdqW48WWAFpkQLTUMkU+E8RySdBtz
         GrGRB8wqBfFdVFs6epToAclMywPuCA5qhGnT0vBo/9+ycn8socOLJc/a1f5iQjg0xlQS
         h6ejgk9CcJ0W8NsgzVn9lakD8ThEWhySmv+eZnYmLKkxvETxA7gz9ADj+GVrmW79VvFF
         BQ7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hOJolEno;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3b9d272bsi7536095e9.1.2025.03.21.13.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Mar 2025 13:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-43cef035a3bso17671935e9.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Mar 2025 13:16:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXgZr9Lb7PudJlH2xeN6oobU7ntYJwfntxQN4lHLGL9B2OKPKuSadBQqqZrwSgzFRwAErM6WYFZ27U=@googlegroups.com
X-Gm-Gg: ASbGncsClCuXwLfTajT3EpJVoTOWb1j2J7B7tvxe7gDToII49FW/3h/z1wc7ahtrXTY
	zsltWIPtInbtd1ltwv41IRcqtOvyd7/uVU5xsWb/yy5SRfTVCYGwSPTarTYcQ6GVNzCDJR1B3zC
	1aagGzJWB7687ihnGU4nzcGpcMbO8=
X-Received: by 2002:a5d:5846:0:b0:391:4559:8761 with SMTP id
 ffacd0b85a97d-3997f94da30mr4175995f8f.36.1742588183868; Fri, 21 Mar 2025
 13:16:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
 <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
 <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com> <t5bgb7eiyfc2ufsljsrdcinaqtzsnpyyorh2tqww2x35mg6tbt@sexrvo55uxfi>
In-Reply-To: <t5bgb7eiyfc2ufsljsrdcinaqtzsnpyyorh2tqww2x35mg6tbt@sexrvo55uxfi>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 21 Mar 2025 21:16:12 +0100
X-Gm-Features: AQ5f1Jrn_9IapCqgYgSltS6n-7mZrLrWLtgtTd5C1mwQlaSaD5HTlmPhaoggwwM
Message-ID: <CA+fCnZdunJhoNgsQMm4cPyephj9L7sMq-YF9sE7ANk0e7h7d=Q@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Florian Mayer <fmayer@google.com>, Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, ndesaulniers@google.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hOJolEno;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Fri, Mar 21, 2025 at 8:21=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >To account for this, let's then set hwasan-instrument-with-calls=3D0
> >when CONFIG_KASAN_INLINE is enabled. And also please add a comment
> >explaining why this is done.
>
> After adding this option the kernel doesn't want to boot past uncompressi=
ng :b
>
> I went into Samuel's clang PR [1] and found there might be one more LShr =
that
> needs changing into AShr [2]? But I'm not very good at clang code. Do you=
 maybe
> know if anything else in the clang code could be messing things up?
>
> After changing that LShr to AShr it moves a little further and hangs on s=
ome
> initmem setup code. Then I thought my KASAN_SHADOW_OFFSET is an issue so =
I
> changed to 4-level paging and the offset to 0xfffffc0000000000 and it mov=
es a
> little further and panics on kmem_cache_init. I'll be debugging that furt=
her but
> just thought I'd ask if you know about something missing from the compile=
r side?
>
> [1] https://github.com/llvm/llvm-project/pull/103727
> [2] https://github.com/SiFiveHolland/llvm-project/blob/up/hwasan-opt/llvm=
/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L995

Hm, I only recall looking at the compiler code when investigating [1].
But as this series points out, [1] can be considered a feature and not
a bug. Other than that, nothing comes to mind.

Thanks!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D218043

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdunJhoNgsQMm4cPyephj9L7sMq-YF9sE7ANk0e7h7d%3DQ%40mail.gmail.com.
