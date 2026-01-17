Return-Path: <kasan-dev+bncBAABBYHDVTFQMGQEMLSQT6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A41BDD38D00
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 07:53:22 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-3831426aeb1sf19500981fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 22:53:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768632802; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gr/5Y6SGvMYb2ei8UKLRhrLA9gxq1KgAZg7RzrmUqLMMC2vQQgxCowFUs6FiqCQmoU
         faEll+LiPKiASAZnyL91r5OBOl31jSJfCWFdC41DwKPKcXn1G8UwRjhyiX1Lxi2PitGA
         FRMMuj9xBGxtIttF6nU2gGfKm0aEimobKtxUBD4aSHPfgtclplo7MMfx1KrMK0C+ENSa
         o4QrbATbQEGqm0XxBJuceUvpMjnZI3rwqWLjWd96KBnCYevNyrGKqY7J2pj/cQxIT2FO
         tEEJco4/cbwkyIfu3IuxZr4MXcsgFlPy7S7reNDwtvtnpkK92F2wvIiQeMCQsOhPUnkf
         AWDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=iAT3Oq4ozD7mxgEKHi3MHkR6z+qEdVaFvSHq05Ufxuk=;
        fh=xz5UbY9a0TBnfOEsbiPe4fYjYygyK+TsTUr4AP6IyR0=;
        b=Y5ZXRrO3hOgCbcz7rfFpt5YmCEzcEdr/VHOrf5mlWkaQ4b+6zpPvGjvKNhef8UVkj0
         WmpcHCbfRcE3kbUQy5WhhoJLvboUj1hfjfOoTOSY3xZkNIAij+Ag8gVvunaAl11s4hAY
         tLSAPtEBV+AMJ3OLZx+1/daG/XgQuPurJOEpNmKL2sY8MBjhkaHYQVPEUQlKvIK4Le9m
         fS6n5fT+RQO8EIMNc57RlTJAK2VxD0Vj2ucWVbnCNQSuj9Q2i6A8iqOyg8o0SGBnFxH1
         jPXFmd/CP/NIMuBfs8rKcuDj/j93qs0pZPXc2Lmcf3kka0gnBTi2pjWU00G7OTKpte54
         8jvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="YZZgSyZ/";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768632802; x=1769237602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=iAT3Oq4ozD7mxgEKHi3MHkR6z+qEdVaFvSHq05Ufxuk=;
        b=ToNUNcgJ6ECjRnlYhkhjieLC5XDrRUR8rtCSUbxn1plRycEdixbGCTQ6/ENjxs81y2
         Nfv0NBBmPj68OVBDuna8mbRP5GqaIVDM37m5Wmh3QGefRGWrpMwZQXRLwb266By+Jtyu
         e1h+AjBi8aJU1RQkODiq7XV6niyeFucrxxPveYCLwFp/CzQ1Qn84O/XVlDYR7ipUJ5Xd
         T31tBoQ7T2E/bgPEK3pbVbRE6bV1EGkmV6VULa8Lxw/0YQ+oNMfh90/mlohEc+6Iyb/X
         OR/FFveBB7qB/9RFWBhPxdkassTC3ztdmXi6dpw6KFgrFEn6xu689N0hdhIVdT5O8R/F
         80GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768632802; x=1769237602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=iAT3Oq4ozD7mxgEKHi3MHkR6z+qEdVaFvSHq05Ufxuk=;
        b=vXOReaP5cAbqmhFFxXYroQdX+kYhNeRnZu5xpuWSEVbZUsq4Ve65eCmZf2zb7aH63T
         upGmwP9BhRLv+Xont6JgfccT5APjGziV8BBfY2QdOTKQH3vJSvfZa5ey52/3SFxmE+Zu
         t4qBjo0c0WLLW5eWoFw//0hPPa3bQUqqKXcQQll6EdJwmhCLHi/XWCX2gCmL5eMUYDx8
         Be/l+uVUZzbIhcMtV4Mld0c9SkOPj0/cvRB0zp9M4Za89lepg73FEB8Khg2wHpLl3/rG
         xR9WctspBXuXQ95HM920j1JyYzlrMwcsw8Gqz2z3X9VZ+LtQJItS9lTZrM49IQ7Lqdqb
         5Cfw==
X-Forwarded-Encrypted: i=2; AJvYcCWITQB6yjJO2VxtpEDloKBVUNyR5I8XDYUpUfANLHF82KdKXmfjsmQyl18zqFIdvC5goXctjA==@lfdr.de
X-Gm-Message-State: AOJu0YyILw1XFtsqCYwYnQ24G3PSz0OitXnmGWzk9G69ZKyTQexDsNXc
	WKew7CI6vgONE0cEckfao8VZqoUzQvbIHiBP6bbggKhhYZVgG2p5CO0F
X-Received: by 2002:a2e:a546:0:b0:383:2663:eb60 with SMTP id 38308e7fff4ca-383866b1006mr14229081fa.5.1768632801599;
        Fri, 16 Jan 2026 22:53:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fsg+DSOt6BUZ35+7Ma0ioSVvqSuClYgqArm1TGo+9o7Q=="
Received: by 2002:a05:651c:254e:10b0:37f:b512:5dd1 with SMTP id
 38308e7fff4ca-3836f090857ls4612991fa.2.-pod-prod-04-eu; Fri, 16 Jan 2026
 22:53:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWRWJEi9XzVG7CKnRvui+k89EHmYuKwKWD7mLfZ4/zJCUuc/2jGtjKPAnExOY76S+det0WalT84+ec=@googlegroups.com
X-Received: by 2002:a05:651c:1108:10b0:383:250a:851d with SMTP id 38308e7fff4ca-38386a25dd0mr12363771fa.25.1768632799472;
        Fri, 16 Jan 2026 22:53:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768632799; cv=none;
        d=google.com; s=arc-20240605;
        b=ikxCTa9I5O+oEh9nU+m9QYkxMCQ7EQKEd1TDiG6h8tIvFnderUGTZcc/GCzBYCC9GD
         3UtI5fiZL/kuBI9lhpulcO+6giLUObtEa6Fh9avnkLOLmiYhb0NR8xxA0LmGsDQcUjiy
         TI6dUyo2oT4/XgSHCWuCAmCx34+fwtFEkwtPIfp9qcybfFRnU7T2iarCsSvrapW1V/tu
         6cxTx3PTE9auwCsrXcUZp30W2Z525E8CINIlB+a32XqvM+A3XP1bdKh1AAxqswywM8Rb
         yWECmPYH5UYkz7y+A9V4mjh9gFcO0clif9zZKwuHwMMbYaCsL9stUAKLmkEixl8yKEsP
         XpsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=mY1/L4vLjuKGDVBMdRgRIO1ljS4pAfye7RfXByDjAz4=;
        fh=h7y4lLUGVbT1Ds52fRLa9C4INAXfD90EjF47xC3gneA=;
        b=A94f7CpZ9zmiw8r+37oRXI1nZsHQed5/LhXpMLkkrxFb64ZqV8fhqmuZA5v34G4ZZa
         1R/cTgAGHj/dzLH2UbdX55NObUovK+oyICACdAdJPbfEvhFDnV+xi1kqfwJw9thC9I+J
         pZJCOTFUjoMSBpE9MjmeH3+4OmqQm1h1UY5kIdhp1GsP2o6AypsgKyjaVWURVGsRt7rp
         bShYQ5EJOn9gPI9iy8lxEyj9ZScfOmZf8hGG8djg3F+5pCFJhOHA7AQfS4ndq3aOBP0b
         cPPshqw6I1IFp/+5gYx23IPNhW/UzrW78cCzm1CVO5LdxV9lwxbjcIfJS/zNN02T/7EU
         gJTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="YZZgSyZ/";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d35eabsi786271fa.3.2026.01.16.22.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 22:53:19 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Sat, 17 Jan 2026 06:53:12 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <aWsxozSMLytabW5p@maciej>
In-Reply-To: <CA+fCnZewHBm+qR=zeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com> <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain> <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com> <aWkVn8iY27APFYy_@wieczorr-mobl1.localdomain> <CA+fCnZewHBm+qR=zeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 031d99193aadb68b322ecc1084a22287a39ff89a
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="YZZgSyZ/";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2026-01-17 at 02:21:31 +0100, Andrey Konovalov wrote:
>On Thu, Jan 15, 2026 at 5:43=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> x86 was easy to do because the kasan_mem_to_shadow() was already in the
>> asm/kasan.h. arm64 took a bit more changes since I had to write the
>> arch_kasan_non_canonical_hook in a separate file that would import the
>> linux/kasan.h header in order to use kasan_mem_to_shadow(). Anyway below=
 are the
>> relevant bits from the patch - does that look okay? Or would you prefer =
some
>> different names/placements?
>
>One comment below, otherwise looks fine to me, thanks!
>
...
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 9c6ac4b62eb9..146eecae4e9c 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> ...
>> @@ -403,6 +409,13 @@ static __always_inline bool kasan_check_byte(const =
void *addr)
>>         return true;
>>  }
>>
>> +#ifndef arch_kasan_non_canonical_hook
>> +static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
>> +{
>> +       return false;
>> +}
>> +#endif
>
>Let's put this next to kasan_non_canonical_hook declaration.
>

Sure, will do! Thank :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WsxozSMLytabW5p%40maciej.
