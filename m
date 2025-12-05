Return-Path: <kasan-dev+bncBDW2JDUY5AORBL6IZPEQMGQEHG2PWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10346CA7D96
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 14:54:57 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6416581521esf2672075a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 05:54:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764942896; cv=pass;
        d=google.com; s=arc-20240605;
        b=bdMfELCCmuYPNFYG4wxZvKeDvptAiZ6vIW9zrqJ6T7NQV17AY8cN1pdpGmmrGd4AZM
         DjG0qvlnnnYt2YuPy4t9rQCo+qu3K4SDnaBhVfHxgNETAYvbnG2s3Luy6ST/AlNaOxUG
         6hbFq+q2fQ2jpIa/79GfH12r7GBzVBeCdiTW3SyrJZTOwflA/8M2Us4PrNF3kXKbmb4d
         en8QwEeNga49jJuBYgt+56IJiTkQEZgOJmyuaFltam/XFmPiWCoKzT1T1SyxN41pzaGb
         j5328Q+ECjjR16zIRCDrRlnLEsoO3UXJlsOxJJOxwjcPPiUk1Bw1cLDtwFYVyxMSNfKx
         SvqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vHmDdOMyGT8g6aYCQCVMwoen6y+nFPEi4dZjjdrzdok=;
        fh=uKASd2hep2evg33T82nBlnQfPgqbRy4DmCsdnGD73yA=;
        b=MlO5ErryEZx3+N2PGAH5+klf9JDDvkTaOqbBqtOb9PUY+aCGzpaPB2AigRYtMb12r/
         uZdhzEPOR+L1lonsVNLDRYJRDePt2z+MPm5VP8SDJaeebNBKfsYAYReeVtg4UuuV0CJC
         PUHIjRMwdNY7VJF8fp1kc/8Btub73icgmA1ghBQSfO8hVZINW319xcd7ik18vSlFAI/l
         k7sXl6y3m2ckSLdC57yLdNTQYZ9CMU+GKFYNP45F/q8kEq8ELWq8wRZtCp9hPFL/BarE
         AljMBXch4RtykNbDRCNoN/V2Qjr9ywTeV2WKsryYUpFuWxSEwuRTVrNdd8LGTAdSFh92
         IGNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=njec55gS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764942896; x=1765547696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vHmDdOMyGT8g6aYCQCVMwoen6y+nFPEi4dZjjdrzdok=;
        b=Etkn2ImtFMzzkfSIqi491CGY7XRZ6as1gtcFdSd8Er7UQOXOwd5vay1EWUWXE3r+oZ
         ov1vLpO9V2nPanou9ueWYJL3SBKpFL27zXS0jGtha7NiGTf/jnkJgoSZ7G653rL7cEpL
         r7xNu10gbmB2wBxrZsROaRm0gxhMJADleJGFJbJGkSjNiHyEpGonZBCriUwqwNZWmmZE
         dQasy+x5zdJhhqC1CC/OZyPgsZGsdjSb+10c83WbdiyvpUIZIWmi+S5Tj0rm1p15I7vs
         xwVTisByXrgQYopV+5FKjnmiU2hOwskMUxcjpVvhxRdfZZm8/o+vKlM3OOfY9i1k9J8r
         Bydg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764942896; x=1765547696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vHmDdOMyGT8g6aYCQCVMwoen6y+nFPEi4dZjjdrzdok=;
        b=jQfJdkCD0iqLtF8E12R41ey0lmMcfJ4Pv4HZv36f2853QFOzbB8lEXl5if1Zb+Sdq0
         hyCjHadT7hA1lsNabGv04vbsgfZ7aVDYpNPFqQET91Kz691KUO1fOcptZ73gRzrKcxft
         RZatrIQHFQrkPQ/TkCL2WIzoG0curNtMqSFfxV4QXNvF+xJhKlXfdq7M+04bVu3rgw9I
         7lK5pdLOkzpD0XrhO/dY/1XT2tZl68cb8Vi19kRLwsaXLwqmwemT1hQqTKp7Mqtc/SQy
         do8nvGJP+aNS9MuUQtXa3VVrVs9kwPRl7XS0B0L9X1xb0/50rJr+xWG6+Pjf28nlYjuc
         1xIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764942896; x=1765547696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vHmDdOMyGT8g6aYCQCVMwoen6y+nFPEi4dZjjdrzdok=;
        b=jPT+4YlVXrUC8pBWsRzRdS8MyhLz4SgJ5MUQBlwGVxWO57W4aCceBbEHsAdzvo080q
         r72VU+JuvyJcqz+shUQgLuh0jOqhcbeKbU4ZaWvF+0BRAqeF8Edbd42VQ12nZtrDFG2E
         66mPFn1ulb+AGFs0pH2I+Y5WP3CtJ0Ra4QEcVQeToFwSd66T4CACavBjazgTZqZgxSJ3
         wg5F3mmdEzxeu8E0Q3PvPzwh0Z9rpPv7mtF9LGkYDndVNYoS2HxlMxNRS7ImvXSJh1cr
         JZyg1P7tPHRCzlbQPSljLcKtm5wT24rrRPlG6OZp3XhzslWbtKO7Y/EtHwp6LtGIUd8O
         vmTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGJngjmapqoyrmL8rPpzT49jODmFFxNlFhT0oocJ6XJFtrAsO65mm9p2F0FpHsOg4YyPXgsw==@lfdr.de
X-Gm-Message-State: AOJu0Yzdid12lG603l2k24CxNSEa3o2XgQrgln2nzf3w3eBLTN4r+CQJ
	uADe42Xmpq5w6m2jNYsk9/1Tp+TUtC967gbMT81nYF1fXSOutCij5hGP
X-Google-Smtp-Source: AGHT+IGg7OSrPTssjkXWeqYLlwY1H8HX4lH/MzR+ScZZCE4RzV8tjQsEaY55dPtwc+ZvnAi+lVp7vQ==
X-Received: by 2002:a05:6402:3582:b0:640:c8b8:d40 with SMTP id 4fb4d7f45d1cf-647abd89657mr5973743a12.3.1764942895878;
        Fri, 05 Dec 2025 05:54:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbzASn2WweKjTjQpgvDH9QpUlbPNPNhC5K9IpTvactVIA=="
Received: by 2002:a05:6402:f15:b0:640:cdaf:4226 with SMTP id
 4fb4d7f45d1cf-647ad5b16eals1674648a12.1.-pod-prod-09-eu; Fri, 05 Dec 2025
 05:54:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDTxb3aIje8qa1lyJlom97bzhyRvZ9CNTdIz9d3CeDEt1PUbVqqAk/BoWyOXEo44VAi5bjDPKrFoo=@googlegroups.com
X-Received: by 2002:a05:6402:1ecd:b0:637:f07d:e80f with SMTP id 4fb4d7f45d1cf-647abcfa799mr5908279a12.0.1764942893173;
        Fri, 05 Dec 2025 05:54:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764942893; cv=none;
        d=google.com; s=arc-20240605;
        b=Cs9hx3uRQpz1NqZRAu7xfj3BV0sPKqIsGusM0uK5yw6LNnnMEJVr91lLQXw8zrcFeI
         a1jc02IdfJXsgn0DElfF4M26oAp4Li8nHBbU6+JlQ+O/nLqVTJArHn4uSH2DDvSHXCTX
         +gswr3ZPpwyHVtpUm2Jn5pBJSaYic/5g3SylOYz80fAWOnAeYQndkiSFhrqeoHcpkG/Z
         BtGFiICRhxp4/s+Qm9mwdfH51gUQtvBkik7PH5OcfUrsbPyEwjq6dx/YgJBX7aoqZ0i0
         9rpusjHMkKjlfAHeK0wq4BgWP3FdlrWFCbf1HDSUCoRwiJks/XHj/lf1CNraGSzSywiY
         soCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XqA0GadxzNDdiyG36a0fVSlW+wUaJcQziD5Q44Wd8q0=;
        fh=lWNnBLDrl3j6yOvm8vEpkGfczUWBMf/7TT+KyO+4i/M=;
        b=bdytMYU2WOQkgvAOFk5sS/qnnQPq5aD5vx7GkpK0IQj1//R0r49+qzoSoiJ3pc+kN8
         rQVUqCoJjFfi8GHi053PHosH8RD/d9YWhrhl2E97vxMxbwQ4dPLhr7mVUNS44BInb44u
         JEZlrgamTlo6lhP89h4jGc6hspkGEPcqZJULb/eyCMPdvfPx36o8TSp5WujLPvWulorE
         UksUliYGCm0ETMFrRtyuMAuBqm/dfLLnkoKPA5TwuW3lZFEQj3XFe6zCrdXNZz2LcL+O
         8iYUuzJ7rtNr8oFfaGO3FSkx1L70gCu0dI1LG6bdalCXhJtmgFSht3+pYJyoQ2H0j+5X
         3F/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=njec55gS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b317f5b0si76918a12.7.2025.12.05.05.54.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Dec 2025 05:54:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-42e2e77f519so1553755f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 05 Dec 2025 05:54:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX1EQfHRRQLUlZkfKqduEiFcSnpaMH51/HNiKth+PTUwRhJ9jQiDo6S1qy14tFjWbhBpEfo32hIx6g=@googlegroups.com
X-Gm-Gg: ASbGncuBV/kMT0ChGGrub0c1XiJ29H/Rs9GclMPD4PXDvp2k5qMqcIhcRR4+9FQj3Jb
	JBoSUnDMSyb50wn8YfdcmiV9TXRfge5ofH26A+H7xSzAx3W7QFd7EXTSQB3Of1z5xNROmVZKJRo
	Ou2h3bFN/i69CdNUlm293LXTXlNaNG4n4NwAO/XjW3tocVlovEHxcGobg/u/6AoE25thCYwSHLC
	+D/tjt/hSmYP8xglNzLPJu3JZbgLWIJGtatsbQ9LP+peqJzfZfT/6Cua1DHpFT3XpE1EM3Fvsra
	+CblivyOB9dev7j1Rvc7H+iKE8xpbQfSBg==
X-Received: by 2002:a05:6000:430a:b0:42b:32a0:3490 with SMTP id
 ffacd0b85a97d-42f7985ea53mr7266209f8f.49.1764942892496; Fri, 05 Dec 2025
 05:54:52 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764874575.git.m.wieczorretman@pm.me> <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
 <CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com>
 <20251204192237.0d7a07c9961843503c08ebab@linux-foundation.org>
 <CA+fCnZfBqNKAkwKmdu7YAPWjPDWY=wRkUiWuYjEzK4_tNhSGFA@mail.gmail.com> <qg2tmzw5me43idoal3egqtr5i6rdizhxsaybtsesahec3lrrus@3ccq3qtarfyj>
In-Reply-To: <qg2tmzw5me43idoal3egqtr5i6rdizhxsaybtsesahec3lrrus@3ccq3qtarfyj>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 14:54:40 +0100
X-Gm-Features: AQt7F2o1xS0hHM8DgwvkRj9a0T3Q-4e4zvUroh1u1jgGrLZaZp4ZkwOF-iWjFVM
Message-ID: <CA+fCnZdHU=0EL2nedasTCRUjo45RHg-U=0JTe6VrAiG=90cm4A@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a common tag
To: =?UTF-8?Q?Maciej_Wiecz=C3=B3r=2DRetman?= <m.wieczorretman@pm.me>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, 
	stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=njec55gS;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
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

On Fri, Dec 5, 2025 at 8:55=E2=80=AFAM Maciej Wiecz=C3=B3r-Retman
<m.wieczorretman@pm.me> wrote:
>
> Thanks for checking the patches out, do you want me to send v4 with this
> correction or is it redundant now that Andrew already wrote it?

Either way is fine with me, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdHU%3D0EL2nedasTCRUjo45RHg-U%3D0JTe6VrAiG%3D90cm4A%40mail.gmail.com=
.
