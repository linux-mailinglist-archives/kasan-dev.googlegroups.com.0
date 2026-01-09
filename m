Return-Path: <kasan-dev+bncBAABBQM6QXFQMGQEJJKYTWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CFC89D0BF8E
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 19:56:09 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-430f527f5easf1804843f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 10:56:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767984962; cv=pass;
        d=google.com; s=arc-20240605;
        b=AcshvThnPZob4oe6PzcrGNZpE8VnbLGg+YTVQx2R3f+LmR94Yt50nPn5vYTdiTeSVb
         ohEhxvxrTwqbHrOCmrXOwZJ7ipRRIbhbyLi1vdS2euu8pey87vdDQQfq0LLQNSGrPPQX
         V4TPvtSkQVHbCpD8VzC9od+nhVazTwk26R+mbkWOWRNMMYAPguJaGum+nFnSLTXEP3/n
         qFU60ehU1UBgH5dwV7EzEj1Pus/kYTSYcLVhlDQTnXauXqH8tgItHu7T07vWjpsXAZq6
         h30H71pLeymnlqJmrQgL5FczQZ8hiIAngkIBPhD/LfjZuUcMTuAjbxsjhwiNUWlvElkC
         lEZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=MUgUQ6jT7OWrPoLMuqaIMtdzs/KqXKgRW71oYIzWY+8=;
        fh=n7KQH8oTzKzMw6YROU4/04tlmfEh3z0CEI7zWdToCZ8=;
        b=QOFTnOcreyBxLW1V5Dv8KaoD5fPtiRfwoKr2jBA1X0hHYrM2H3nWbnPbxVO/U8fpyx
         ycBwJfxO8siNvJ0cmbM1/eDLFgCs0FkY3feZOzdPEe0mtSbW4GPDRH9Bb4eDhjr91X/A
         vi5bvpzrXIi6wuNR2WLZ7WVWj6tiGOMAyK9U3gS2CLYtxbE328BHtcQEwS44Xe5xf8wL
         T4NoDQVQvSyMGigEA6hwZdckZm75oxVvQb/I6x6LZdeHJsP1H9PwjX0OfR59eRDfksjR
         W/DyDC+wieUW43ptHIkodR1gCeqmfjl9bro9hToBqmaKnqA26bvKJWhnaU3qEUUpODiY
         nFBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DxtMSMqf;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767984962; x=1768589762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=MUgUQ6jT7OWrPoLMuqaIMtdzs/KqXKgRW71oYIzWY+8=;
        b=pJMjEz4fVnWTmiqiSlDrSXPyrbgNtPb0YIVrgfKkZFOt/yFweUgVvaKn+pwucBY6Y5
         Yi4TIzBDRLi+6Su3fCZpa47o5S8vi+cjYH5sjwCbH7qd4fPDK+tR8rHhP9Z65/G2ehUv
         +1zF0v3fTAK6QBPAkm5xALypJCvfstBX4eO7R5Hvqb8DtjjaT9JH+L/NUzUZZfESESwe
         rp0vrDCeTX6Hy/4jZj2jCGLZCk3rzx8BOasgvCqqT9Rytg1NZ3dCwL5Wd4RzG3z8r4MZ
         eEN8AOn7irSn/xtafoUxBajrbmxjs/cYDVD6gKEnCAx9vR5dGV260ySeDTiPjMjIbtB2
         X7rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767984962; x=1768589762;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MUgUQ6jT7OWrPoLMuqaIMtdzs/KqXKgRW71oYIzWY+8=;
        b=mFlGzn499z3l68HWItPCk5m3HFPbIzlbMItdk30g7W7JNawwuY7g15kgj4roII3aCM
         zo9GNn3e2dl+taVYDajbVeDLp5q3px7gfIezXKm4TLYXvQ/tCqJJniiogdUiQPJs4+yw
         VqWz6SC5wLU9CNure85ieYgplCULX+FB1lxsFnVlNgBD+Y/hQMrYqiDIAnZ0MO/Y46S+
         rR1/6qK8OUIS57mKA9N0pba1x5RGVvzpwxtw//b4W0LU7lTArdgil4dstRgSke5T42Sx
         F9GUkSsgmh+bjSGrhH6XKyZvnmZoKzt39XqF/qDQmKINoCPX0ye2qKzoFcxPdX8bzIKV
         JutQ==
X-Forwarded-Encrypted: i=2; AJvYcCUWv9cXOetsLXTG9zFkgDf9jcNdRBXm8d3HjEFCX5M5UmRpOZVgMqPDgzq+7hxySuJtT7QBCg==@lfdr.de
X-Gm-Message-State: AOJu0YyXFl3s/4+4ZuZPCtFtt/zmuqGYogoYfGE8Dqxfqn8X+ieogflr
	PqaOe7Dx0xgv/mTW+8iKEuIXKErXlMmWscyIQkFzOBwNuRNUS/nLf3Ob
X-Google-Smtp-Source: AGHT+IHetc0+FPQ0FbQBjy7ZRZBFTJiUKo9hqagFGJxwOKcqZWehKfzfjWmYFuxa4h1670XBZEsEpg==
X-Received: by 2002:a05:600c:3541:b0:477:9fa0:7495 with SMTP id 5b1f17b1804b1-47d848787e3mr139268485e9.14.1767984961820;
        Fri, 09 Jan 2026 10:56:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZPLAMgsSiNcfyr70mtXJyu8gH/BYNJB7Z+wy9jfBwgyw=="
Received: by 2002:a05:600c:5246:b0:477:9e7d:40a2 with SMTP id
 5b1f17b1804b1-47d84884e51ls13598915e9.0.-pod-prod-00-eu; Fri, 09 Jan 2026
 10:56:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEo0YO6Hch5d+g8xYV/hGkLsv8z6HdYDBhi4WgekJ+1CKcdOpWQJ6oN/OHdF1qsaZxfJytlvtVfas=@googlegroups.com
X-Received: by 2002:a05:600c:3541:b0:477:9fa0:7495 with SMTP id 5b1f17b1804b1-47d848787e3mr139266995e9.14.1767984960016;
        Fri, 09 Jan 2026 10:56:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767984959; cv=none;
        d=google.com; s=arc-20240605;
        b=ADldfdjmLEbQlrJ57kOL+JGDcN26c0uO6mwx88GZcNew3LkYeTXokoJaRu9ntqLmTr
         wvNsvg5oLqLwK5qP/kcEEZP2Q9jxiWb8Cv5P5pN3zFWniQtDz9WD1Mz/0CNv+Xn9fkEx
         UYnYXJZgvObxaJV5CeFhpzjJAEGbxVpIvtihZxfT5omDwk+NFgTsoj51CQE3ZU/lkZCn
         6h6eJdBpSBGVPnXeUFaGN7Bqc5vMxOIhhd1HpEqtasJjSicksm/SpaRQkXQNApNp9bly
         7ovND40plK31Rvkd49RLgKBBesLKhO0p2QUFbPinrOxQWCbmwHT9qpnoUXLDazv8z/Cd
         1sIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=UALVR12QqyIFzAEC/BHtozvGGQ/3JPuZHtUGAMu4oTI=;
        fh=M5mZ1dharuj/Xn5/YrvK0DyTcE3/xORGkWds/8iqwuM=;
        b=hKFTvc+tbWgqQUHrzg5yTSnYiPEEVtKJxvO2yExB6yxgm3FLW2geZbUI+mH5da7Q09
         R9wD5Pg2hD8KyIj12IMjmsGzyNiNcuztFXjpvfSkXwZ/XNPVVKDaDJduLIAdwtdT7W2h
         mORXaRiHh/EYS/1EWreM3dK47kcimxp5Rl+TCJpFVvBD63nSK8hBCEC/1jzjFs0nJjFj
         jCitmEtup8ysN5/fAEbTXZCkuE3Ltc53OkYeY2XMfGCrvG13+ZAYb/sgZHfBORppjfnW
         g/uabIMKGSWeB5l3aLPEfMn1oM2ZFXdYTyiNtIYzqui39vHRKUu8avjKcyNkelVBUEIp
         E1Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DxtMSMqf;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10630.protonmail.ch (mail-10630.protonmail.ch. [79.135.106.30])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47d8707eacfsi483775e9.2.2026.01.09.10.55.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 10:55:59 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) client-ip=79.135.106.30;
Date: Fri, 09 Jan 2026 18:55:53 +0000
To: =?utf-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Subject: Re: KASAN vs realloc
Message-ID: <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain>
In-Reply-To: <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com> <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt> <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com> <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com> <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 1cbd7ae2e801abbef632dd9ee50f89616142157f
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=DxtMSMqf;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Okay, so as I understand it, the issue is centered around adding a size to =
the
pointer - because in that case it can be unaligned and it can trigger warni=
ngs.

So what do you think about changing these two:

		kasan_poison_vmalloc(p + size, old_size - size);
		kasan_unpoison_vmalloc(p + old_size, size - old_size,

into something along these lines:

		kasan_poison_vmalloc(round_up(p + size, KASAN_GRANULE_SIZE), old_size - s=
ize);
		kasan_unpoison_vmalloc(p + round_down(old_size,	KASAN_GRANULE_SIZE), size=
 - old_size,

From what I've read in the code the second argument should be rounded_up() =
at
some point anyway. In the shrinking case we don't want to poison the last
granule of the new reallocated memory chunk so we round_up(size). And in th=
e
enlarging case it would be just as correct to give up on adding anything to=
 the
'p' pointer - but that'd be inefficient since we don't need to KASAN-touch =
this
memory chunk - so we round_down the lower boundry to get all of the new spa=
ce in
KASAN aligned chunks.

Did I get it correctly? Or is there some flaw in the logic above?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

On 2026-01-07 at 22:55:21 +0100, Maciej =C5=BBenczykowski wrote:
>> WARNING: Actually I'm not sure if this is the *right* stack trace.
>> This might be on a bare 6.18 without the latest extra 4 patches.
>> I'm not finding a more recent stack trace.
>
>Found comments from Samsung dev:
>
>But another panic came after those fixes [ie. 4 patches] applied.
>struct bpf_insn_aux_data is 88byte, so panic on warn set when old_size
>ends with 0x8.
>It seems like vrealloc cannot handle that case.
>
>  84.536021] [4:     netbpfload:  771] ------------[ cut here ]-----------=
-
>[   84.536196] [4:     netbpfload:  771] WARNING: CPU: 4 PID: 771 at
>mm/kasan/shadow.c:174 __kasan_unpoison_vmalloc+0x94/0xa0
>....
>[   84.773445] [4:     netbpfload:  771] CPU: 4 UID: 0 PID: 771 Comm:
>netbpfload Tainted: G           OE
>6.18.1-android17-0-g41be44edb8d5-4k #1 PREEMPT
>70442b615e7d1d560808f482eb5d71810120225e
>[   84.789323] [4:     netbpfload:  771] Tainted: [O]=3DOOT_MODULE,
>[E]=3DUNSIGNED_MODULE
>[   84.795311] [4:     netbpfload:  771] Hardware name: Samsung xxxx
>[   84.802519] [4:     netbpfload:  771] pstate: 03402005 (nzcv daif
>+PAN -UAO +TCO +DIT -SSBS BTYPE=3D--)
>[   84.810152] [4:     netbpfload:  771] pc : __kasan_unpoison_vmalloc+0x9=
4/0xa0
>[   84.815708] [4:     netbpfload:  771] lr : __kasan_unpoison_vmalloc+0x2=
4/0xa0
>[   84.821264] [4:     netbpfload:  771] sp : ffffffc0a97e77a0
>[   84.825256] [4:     netbpfload:  771] x29: ffffffc0a97e77a0 x28:
>3bffff8837198670 x27: 0000000000008000
>[   84.833069] [4:     netbpfload:  771] x26: 41ffff8837ef8e00 x25:
>ffffffffffffffa8 x24: 00000000000071c8
>[   84.840880] [4:     netbpfload:  771] x23: 0000000000000001 x22:
>00000000ffffffff x21: 000000000000000e
>[   84.848694] [4:     netbpfload:  771] x20: 0000000000000058 x19:
>c3ffffc0a8f271c8 x18: ffffffc082f1c100
>[   84.856504] [4:     netbpfload:  771] x17: 000000003688d116 x16:
>000000003688d116 x15: ffffff8837efff80
>[   84.864317] [4:     netbpfload:  771] x14: 0000000000000180 x13:
>0000000000000000 x12: e6ffff8837eff700
>[   84.872129] [4:     netbpfload:  771] x11: 0000000000000041 x10:
>0000000000000000 x9 : fffffffebf800000
>[   84.879941] [4:     netbpfload:  771] x8 : ffffffc0a8f271c8 x7 :
>0000000000000000 x6 : ffffffc0805bef3c
>[   84.887754] [4:     netbpfload:  771] x5 : 0000000000000000 x4 :
>0000000000000000 x3 : ffffffc080234b6c
>[   84.895566] [4:     netbpfload:  771] x2 : 000000000000000e x1 :
>0000000000000058 x0 : 0000000000000001
>[   84.903377] [4:     netbpfload:  771] Call trace:
>[   84.906502] [4:     netbpfload:  771]  __kasan_unpoison_vmalloc+0x94/0x=
a0 (P)
>[   84.912058] [4:     netbpfload:  771]  vrealloc_node_align_noprof+0xdc/=
0x2e4
>[   84.917525] [4:     netbpfload:  771]  bpf_patch_insn_data+0xb0/0x378
>[   84.922384] [4:     netbpfload:  771]  bpf_check+0x25a4/0x8ef0
>[   84.926638] [4:     netbpfload:  771]  bpf_prog_load+0x8dc/0x990
>[   84.931065] [4:     netbpfload:  771]  __sys_bpf+0x340/0x524
>
>[   79.334574][  T827] bpf_patch_insn_data: insn_aux_data size realloc
>at abffffc08ef41000 to 330
>[   79.334919][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00=
000
>
>[   79.335151][  T827] bpf_patch_insn_data: insn_aux_data size realloc
>at 55ffffc0a9c00000 to 331
>[   79.336331][  T827] vrealloc_node_align_noprof: p=3D55ffffc0a9c00000
>old_size=3D7170
>[   79.343898][  T827] vrealloc_node_align_noprof: size=3D71c8 alloced_siz=
e=3D8000
>[   79.350782][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00=
000
>
>[   79.357591][  T827] bpf_patch_insn_data: insn_aux_data size realloc
>at 55ffffc0a9c00000 to 332
>[   79.366174][  T827] vrealloc_node_align_noprof: p=3D55ffffc0a9c00000
>old_size=3D71c8
>[   79.373588][  T827] vrealloc_node_align_noprof: size=3D7220 alloced_siz=
e=3D8000
>[   79.380485][  T827] kasan_unpoison: after kasan_reset_tag
>addr=3Dffffffc0a9c071c8(granule mask=3Df)
>
>I added 8 bytes dummy data to avoid "p + old_size" was not ended with
>8, it booted well.
>
>diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
>index 4c497e839526..f9d3448321e8 100644
>--- a/include/linux/bpf_verifier.h
>+++ b/include/linux/bpf_verifier.h
>@@ -581,6 +581,7 @@ struct bpf_insn_aux_data {
>        u32 scc;
>        /* registers alive before this instruction. */
>        u16 live_regs_before;
>+       u16 buf[4];     // TEST
> };
>
>maze: Likely if 8 bytes worked then 'u8 buf[7]' would too?
>
>it will be 88bytes + 7 bytes =3D 95 bytes(=3D0x5f) which is in the range
>of granule mask(=3D0xf)
>
>I don't think it works, but it works.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WFKEDwwihxGIbQA%40wieczorr-mobl1.localdomain.
