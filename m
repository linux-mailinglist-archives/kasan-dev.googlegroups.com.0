Return-Path: <kasan-dev+bncBC7M7IOXQAGRBU4G6TFAMGQEF2DAHMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D436FCF85C3
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 13:43:01 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-88a37ca7ffdsf13977656d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 04:43:01 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767703380; cv=pass;
        d=google.com; s=arc-20240605;
        b=CjuGcz2uBkL21c4tG1XxZKpoPPS+Wl93SLUcN9dZy6HTPBtAh02m8Sk3gXRM1viSqY
         JWDzRZ+VbK8lopbOGRZMs1TosHRQ0Jv8oPXS/1ww2Kqq7Ydy+EGH+yCZmjUk2vlN0yIS
         J9/JwAMbkXw//ZKxrFG/19Rd1SWVjOom7gn+h4D+vvf/gwzY5Y1IXzkod8RbzDi1L+up
         BxCxTMAst4InJIyu7+4bgGF6vR1HUukWpA5Lk+V3MOBJk+PVEFJzagfVhs7+25t8Zst2
         xbAiZb2fspW5eHCzpvaA/YawBcAYZFeUeovYA/yFcq1mNWkpAy/eqq8F/Pzmi4B9oAVk
         bVuw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=JmTYkBRVfxHKl/wGaoL24o3akhfT4K682i7+B8VYADc=;
        fh=cBzD3WbFjgLTFPoOxFH5BZ3yl/Bs+2QxPSYN9nldi+U=;
        b=M6Ltk9vr77ca5SP1VvGOfmoTYoiHR8mJwnoIhTgNaWqXPPyLzMGbk17auG9VedtlhZ
         VRRKLuqGKKzZ9M2lquLcKS+8/YMMF8YL3pjKLrXlCPFlipsDIOmfgLjrYVaFfudKgXjb
         ZbBe7n5JAq/ltsriFDMOOPIewlngRJ5L3Z1XKtsEYJO2MW8tS8FGuzdrQ7l7Tsx7fbtu
         YWqCrXUh5krcHWMs+xxUF8iGBBXmbLOUNRWoatgeNku3OG3Mj8Mq6Qtf8HSaQLoP5UKE
         ZV329STVIVGjEo94OieT3PZ6c+jJyjmK8f5Stt6EM+E6Mq+QsvqP/xbd69afMA/946FB
         tOnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KwvLm8qI;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767703380; x=1768308180; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=JmTYkBRVfxHKl/wGaoL24o3akhfT4K682i7+B8VYADc=;
        b=a+HzeoUMaZ6F64neC+s92qx2V5uV9+JnJnndAKrHUoZmGZCuWdICCKbhKxf78f2o8m
         VP7bxhV7XW3xeF6H2V+xltnFcGkeVGZrZi27olQEB4e74paAQd58Z+LLuHX58EPP7jQu
         vUNjgO30o2LzI3eWliwJnUU7Osco4zffQDKowv/m3GaYwK7psXXNJY7oM9L/keWIJg2f
         r5uWdVINLFKpJco4Pj+LH0M62S80m8HFi14RkZMAkIu7ltHIl9G42LSCJFUFHJ4walwF
         4aXcsZjDMRlDyTbeaKoaSjYWDrODJToY1K/P8oj1GGZee+vPVZIdIHzut6VaQcgoCdbX
         fXaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767703380; x=1768308180;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:x-gm-gg:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JmTYkBRVfxHKl/wGaoL24o3akhfT4K682i7+B8VYADc=;
        b=CbdMT0ZqCBhyHSQ/v8Y6/hb1DsiBPHaqZHXhZajaefa8yjUsCq06NbX5S3e1tWk7+T
         H6cEbufabzXct52Nphuvy8WN4H4Sw9d3kVK/GQsKwNhCXJZbeih38R7tr6zFcqcfNV6N
         ell5Tt6aksUQKVyGEGeMRfh9P0CjtFSIjABbaIzHgr79ZhrSjvOToqAqgVJ0vAy0vQu7
         eB2nca+KUKaHoBuPFm41VFVRUWR5OeGlygV04zUaCuiEy2h7vpNk8QOtmfR9bu8LCI28
         wt+gaL8xB+VwczSWwQoIc9x+h5A81ezrKf6U8v4XCGPRQ9J0k1gdmpt6HIFNUugU6wpT
         SFbQ==
X-Forwarded-Encrypted: i=3; AJvYcCUdj2xcaPdiZc8TOmEh14jaOQk/D/90xiln4Op6XzuRAsQlkx6EveJx2P6CZ09jkUJhvd+fVQ==@lfdr.de
X-Gm-Message-State: AOJu0YyS6m7wvrxkR0zr8ZaleT/3B9Qej4UUjrJRDMKbP9nWWbsgLKO9
	ch3EvXl+9hyLmJhiUrOB8xlYmmMDvMBg/CtSRrO3GHNxwKXtPXPlHWBH
X-Google-Smtp-Source: AGHT+IFJ/21HQmp24+1qoW9joePAapdhjiA5UOJ4pGD1Dv5UWjOx5rBR053S7U5GnjK+mk+GqSG+lQ==
X-Received: by 2002:a05:6214:f29:b0:888:8174:5bbc with SMTP id 6a1803df08f44-89075c5a6admr42281456d6.0.1767703380141;
        Tue, 06 Jan 2026 04:43:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWauAjIvsdzuPKFmX0+QOinYe0mC7rrz0QmAyd7erIg1SQ=="
Received: by 2002:ac8:5dd0:0:b0:4ee:1b36:aec4 with SMTP id d75a77b69052e-4ffa70d545cls17557011cf.0.-pod-prod-08-us;
 Tue, 06 Jan 2026 04:42:59 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVF/rbgALVCZ0UnjW3N1gOi3r3A71vKemafHpMI3lh02E1hYJmcfphWLJ/0Go5PPeUE2b5P85pni4M=@googlegroups.com
X-Received: by 2002:a05:620a:199b:b0:8b4:3ea8:b30e with SMTP id af79cd13be357-8c37ebbf37bmr377845085a.46.1767703379188;
        Tue, 06 Jan 2026 04:42:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767703379; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nw2/9Ttd8uD+qMrXqoPi11TyWUDYchwDvZtGIm46jy12RGLBcCZCo1TA2GzFW00+L2
         ncZlysQKfiilXACcY27OXVe/+vOFQ/YmhOz0X4n8GWSqpN5Sr1G597/+5SspliZWnvK3
         Du7KVXJWsVSvqzPoDUkmy0TJ2DQ9aKxsJZ6nS5pR2cg5J+JQp3x8EX5k+SMErMbr6pWj
         Wyk5z5aSzQHAfasRbwZ9M1QPsSJ14ZifPYnSIW1D8hWTaQn4uCdlvRS01LNfPxLypC4g
         1SI1lBnY3w/ECr3LMAcmcF9nLv+cfni8JbIOmCU0ihUxpzRDe2Pr/YJ0kY9FAlcTjJyc
         3CBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:dkim-signature;
        bh=6VaaRHRd5E6uRpWJGcDGRBcsl4ux3CBEvtldX20kevU=;
        fh=Zw19rlWpCB4wP0j0BbbuvKE/nOhR7O63C7teIdK/VeQ=;
        b=RFJf319TgMSNkxr+TZGSBFi8Hnvmc6fnsNo0xF/M2sDP+E9uuIdC7KV6bd4aBAPd/t
         08yQLEXodgu1Kf0Gq+FrN8/kUP9X4ECVqCx1xUlWszAsjwtOa+FEWUN3mNPY8X+NAP5V
         OVNI2WeWLwZnaSNQ6w+vD/s2EM2IFw0WzfmUGIKnPrkXrak2e63EG6ut6TWP2QF3pc7q
         yYuP+L0RD7CaEhQpUXViGsxtbWL74GqEeq55hPkVBrvK0lFVhTipB0kOKDvGfygSZOdT
         oaKTB2HT1c25XFDt3nIfWC+z39U6G1RtTSfku1Ffj3nxwpvKmDUVCvHL1Zr8Ffc+pVzN
         9gmA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KwvLm8qI;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89076fb9c33si41816d6.0.2026.01.06.04.42.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Jan 2026 04:42:59 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id d75a77b69052e-4f34f257a1bso315451cf.0
        for <kasan-dev@googlegroups.com>; Tue, 06 Jan 2026 04:42:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767703379; cv=none;
        d=google.com; s=arc-20240605;
        b=C1Z+E3Tob26lIQGGzsA4apARwQ2poLcBXTUv8zDKcWCsqKdnQYbJA82ZK1luc0G1eG
         BGGIzq/2HQQCqarh7lZO1+s13z/Lb1aCS9gzW022O8PhvSl6fywluU2rSDt4GjNTn6Fu
         c02bYtuFmDYIv6XYCHUZviKbfU6RVgSN6CnjIV1F1oeb5oEQvFkMUqz50JOOQOFqY7hz
         3JhLgfT/tgmx1FoWAT7qbVu+xFhII07aX7Q1om1BG/mkCTwfXjSc47H8krlFtFAZYaJm
         cDdenXQtj04H/yEM4ArCG3aLAhJHkV4POfL6C9695Y0q2sa9Lu+FSOEh4/5vDf7KixNP
         dQjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:dkim-signature;
        bh=6VaaRHRd5E6uRpWJGcDGRBcsl4ux3CBEvtldX20kevU=;
        fh=Zw19rlWpCB4wP0j0BbbuvKE/nOhR7O63C7teIdK/VeQ=;
        b=a5+wWXbA4WZePqD/mQC8zF52dy+m/8GFYyU77JYq24WLqlBb+OSSreNZlf5IThJLVB
         f8K1rXpVe9JXmJiehjj8XO4I3KQPN4on4A4fRwTuPnFUU5fITkFCNhnLPefzvbGjQOtx
         9iH0yUOIR7/57eRPzewYUFfkjyPr0LZYwOvN5HI7WaXwiLEB6bmTRya3kdcORzvR2qYA
         w5QCUJOZn3+rBxxZhg4U/GsIeBa5lm1JXDUbFe9TRFmErrPhYXo5iu0eyv89HzoE/KWB
         gkcXKFeM1whehg0H2L33ohaw0yIlze7AK3CcsBaLgEeyfRz0o2l+kJSDyNXAkeoUzoMS
         quJA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVQyKEpuoNORkcxY+tS9udmtID4q2uXp9XJ8JCgntc32s7zDz0C1j+TPA68LiUEvYZ3ml6AD/NIklU=@googlegroups.com
X-Gm-Gg: AY/fxX5kj0fb5w+mVetdnJuEny3NsvQd1N7mj3HO99ISWtG2RpPTdXk1TNP+aJvXIeU
	KfQCHh/DN5+ak+8vAd7bw7aGwTtJVtq3HXLJLAI9R3l1uanpqs5NacPY/a2nvs0bSFwxLjla8mC
	s7Gj/rA6wUS/rYK3oW4f5koMSJFQFOX7sOKu82I5rcvrcGqTQdBQitiZg3z0NJhbW87nyKZFa9X
	E76K64OvAzY9X2GMdPnq7WEKOEbNFNsoiLcXQbsbQpxdSPAMRKWAucSNuIX5CzD3YlwWmNteCFC
	zT0RO5JMOL/yRvtWQnBvbHb6h+40rAMfLHewHhM=
X-Received: by 2002:ac8:5fc5:0:b0:4f3:b0f3:62bb with SMTP id
 d75a77b69052e-4ffa963a05cmr9713571cf.13.1767703378488; Tue, 06 Jan 2026
 04:42:58 -0800 (PST)
MIME-Version: 1.0
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Tue, 6 Jan 2026 13:42:45 +0100
X-Gm-Features: AQt7F2qAI1ZtC3RYWs2Wp-HOwXoK03sV5LG9X9mZr-LKGvVUmzl8KqyB9wnW6k4
Message-ID: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
Subject: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: joonki.min@samsung-slsi.corp-partner.google.com, 
	Kees Cook <keescook@google.com>, Andrew Morton <akpm@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>, 
	jiayuan.chen@linux.dev, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KwvLm8qI;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
Reply-To: =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
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

We've got internal reports (b/467571011 - from CC'ed Samsung
developer) that kasan realloc is broken for sizes that are not a
multiple of the granule.  This appears to be triggered during Android
bootup by some ebpf program loading operations (a struct is 88 bytes
in size, which is a multiple of 8, but not 16, which is the granule
size).

(this is on 6.18 with
https://lore.kernel.org/all/38dece0a4074c43e48150d1e242f8242c73bf1a5.176487=
4575.git.m.wieczorretman@pm.me/
already included)

joonki.min@samsung-slsi.corp-partner.google.com summarized it as
"When newly requested size is not bigger than allocated size and old
size was not 16 byte aligned, it failed to unpoison extended area."

and *very* rough comment:

Right. "size - old_size" is not guaranteed 16-byte alignment in this case.

I think we may unpoison 16-byte alignment size, but it allowed more
than requested :(

I'm not sure that's right approach.

if (size <=3D alloced_size) {
- kasan_unpoison_vmalloc(p + old_size, size - old_size,
+               kasan_unpoison_vmalloc(p + old_size, round_up(size -
old_size, KASAN_GRANULE_SIZE),
      KASAN_VMALLOC_PROT_NORMAL |
      KASAN_VMALLOC_VM_ALLOC |
      KASAN_VMALLOC_KEEP_TAG);
/*
* No need to zero memory here, as unused memory will have
* already been zeroed at initial allocation time or during
* realloc shrink time.
*/
- vm->requested_size =3D size;
+               vm->requested_size =3D round_up(size, KASAN_GRANULE_SIZE);

my personal guess is that

But just above the code you quoted in mm/vmalloc.c I see:
        if (size <=3D old_size) {
...
                kasan_poison_vmalloc(p + size, old_size - size);

is also likely wrong?? Considering:

mm/kasan/shadow.c

void __kasan_poison_vmalloc(const void *start, unsigned long size)
{
        if (!is_vmalloc_or_module_addr(start))
                return;

        size =3D round_up(size, KASAN_GRANULE_SIZE);
        kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
}

This doesn't look right - if start isn't a multiple of the granule.

--
Maciej =C5=BBenczykowski, Kernel Networking Developer @ Google

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA%40mail.gmail.com.
