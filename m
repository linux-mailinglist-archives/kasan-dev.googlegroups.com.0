Return-Path: <kasan-dev+bncBCSL7B6LWYHBB45TTLFQMGQEVP4I3NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 081CDD1AFD6
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 20:16:05 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b77f5f4cbsf3846353e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 11:16:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768331764; cv=pass;
        d=google.com; s=arc-20240605;
        b=i/q58We/T6SsTe0K5//Jy1dzXzGETi0f7gQHKFzhNsSRX9wKA/inELXgDsYkggRyKU
         V0DGd1NIY7hJzSj1g3+9ZjRzFPq22qmYT9CcVASkBM8722AZf16x5dGIC9LxrJXzrSMu
         JDW1sLpPx9bkcsD0hPQg34BQXVZp/oYsC1jx0jj2woLl8OaC9mv9W9H8zB0WnKTde4Z2
         0CXAq6h6awS1PQkUnHFSdYuYMSS8LymKvcxkCQ6mYwmEFDMZ0LlNqtKl2LxZTucp0lWr
         FmSnPemE6t2nbW4aTZkwQImSi0n+f/P0rjKNkoXh4mvSeZxYgeS9AKRte7Jt3//EvXfT
         qEqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=vB9vy8HB8w4el6/ka904SPCjiaTihRmTqUPwJExAFdc=;
        fh=7vfP5BH8b/t5Lwy/ls37E5+4HTSJlxOej5FMK38zN24=;
        b=HK8FjQER6dqt3bsQKMb4ffNqebDJBsIt7N8a+F2IHEruo8vwXzz71dS1xOeNKmFj1i
         F+hTr0QEEbDWPTA6HaexEhR64vpuuxgPmZ91ZSxSr9XvyFsxWBEAPfe1X14XuSHxPhyz
         zleR/X/r8vxiAp8vtbpvcMH3AifWgpyypgjqQB1CPNk87V8YFRiuQRWgr2ki2KfGnXXp
         M7FUBRGzeOnfZdluHTu1mbVRCua/xqPh0cVyim+3bEPeGVhULw7nDSefAYrZTYiBIPBM
         2x5Otn4QqU4CrHV9KxVsHLV3NCBnaUd9GkBPYysvuIK7UVr+hx3rvDTb1OuDoHEjgj85
         /6rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XObCGkMj;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768331764; x=1768936564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vB9vy8HB8w4el6/ka904SPCjiaTihRmTqUPwJExAFdc=;
        b=WhSU1TfvNTZthbglEkjHAFN7Z6cm5q8Cg3g8an789uwXtGPdUu9V7p6ekqZDB8onpW
         axed9I9jMOe769BuLsSUCgykZS6aregXocok212R8W7iie7RedRs7aedBErS/IcNvOeP
         6msuAZH5gfvh3UhOcZPzOXNO6Nuu60Tv/AJTy/AKp3YVqkgzA4IE4Hoj4ernGFrrndEg
         cFdPvXTkx5ySN5bFDp7QASMm+iNRMa7E2X1PdIVD/WLJ3nXBU02xCMQsJps2EyXYC3wE
         5jSKPJNJmPmMt5RdJjgcteQHGT3gRff34YTTa1RHHWbGqbjzD3EuIbOUaBxv7MQsHq8U
         wYvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768331764; x=1768936564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vB9vy8HB8w4el6/ka904SPCjiaTihRmTqUPwJExAFdc=;
        b=UbvC6MP9kCxxFXJjkI87fJgI37+pwCsXpDvy1Sr/pdaMDaJbS4hdLtyOY1sQvPrHwK
         RYaPlzF81V+7EVT/2EFcf+FVXoinL73w2Bd29zmvxSO9/SUxZ6ANgzG58VlXwQ6ZdHlM
         49awBvZFHFalg/q+qDT2WGrrhOeLhwrgrys2R6X298r6xxv0tPYZQZgC0FizqnkC2AnO
         0dqWftpR3O1rI8jOxVJCAnY7rB3ZT+w2EPtwj4ZmUbL3cSrKzMKTVc538cqqJA5mVq9z
         BeoI7vsAPqfA96zmzLy4LT3WEW+SkoQKq8S2i6hvLzQsR6ZLuv4eboXBU4Y12A2kDxm6
         OC6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768331764; x=1768936564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vB9vy8HB8w4el6/ka904SPCjiaTihRmTqUPwJExAFdc=;
        b=aG+eKS6ei2lTyDw8vYQkXAj+JQxGr0qGLYL9KpREkMRqWuqmwscOSiy0t1QAEpycz3
         cnNItNhwrUeIudmZvO4jxo64ojupMYFB96C0fSo1hFOv9WyuO8FM3CYMYh14b3Dwe4QK
         KALHZqo7iAvvPknOb/tSoMBYsKEYIAjy03sORJaGqpGG/dV1NLWFLBtrYxvAtMXmN9BG
         LppPSmphcUaeLxrWMTLwredTmZPsnYR6QzYPGIGZrW9FkmJ4IbSjnn4FKHk0fc58vGlK
         QEWOj+vqUO06Y+5Qd7XV2m2gIfuNOh6E6Xxbznrlp7eBl+T65SqR1D6VRSyOSZWRlHk0
         rpOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsgYC6TPZ72eYKOEWIKijOU+VVxFcKSkArcUKMzKXbNczTO8LIpgOKJxD5gMYQZhI7RudWwQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUK61PydxWDIiXaQiO3lBKS4I8i1QSl3RwvxqvkOY/grlGL6BJ
	q//yI89hJTdE2gsneOSzQSE57sZGUYKR8yaLex5+k3LAxRvhwQGEFreY
X-Google-Smtp-Source: AGHT+IG31Em1hvRRdb4cZq2mieGRWZXt4orfUR9jEjCdT16ozJLA96sbJ+D+gdVDtHc+IAZFDHVKeg==
X-Received: by 2002:a05:6512:238c:b0:59b:794e:dff4 with SMTP id 2adb3069b0e04-59b794ee18dmr6287935e87.48.1768331764137;
        Tue, 13 Jan 2026 11:16:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fdc7/E98UlZ2Bm5/8WN35ev4OGbP9uTP69mDlAcrPtuw=="
Received: by 2002:a05:6512:2c0e:b0:59b:7205:469f with SMTP id
 2adb3069b0e04-59b72054791ls1486556e87.2.-pod-prod-01-eu; Tue, 13 Jan 2026
 11:16:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbsF5Ks4Gl5BzBLfvTWadSamKzy4YQyFsBh62TmhARYdIOZkwZFu5GBSb0lvrySmeQXX5smzUgc9g=@googlegroups.com
X-Received: by 2002:a05:6512:1090:b0:594:2c64:54c9 with SMTP id 2adb3069b0e04-59b6f04d369mr7228985e87.37.1768331761139;
        Tue, 13 Jan 2026 11:16:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768331761; cv=none;
        d=google.com; s=arc-20240605;
        b=kLyvpHWdzONe1V35Z+WlhYgGnFk8KXSPmVIivTTD10MTzcPT0kUp5FmiiiE9YfXPPh
         7fqLmDBP17ThbrOhTQxBYhP3LA+MvLhqMQS1NDiqH3TqE60QRpxG9riLrGkoOgZyDzcc
         UFZheXqr+B8mDg8UbgigjizuMmdWehQfk9a+Vg6fvBFsHyRPouPZAfAgnVZYJvRX5MaX
         9IjukRuG8CoRzRJApBcSN3jpasVQsv3mbDkvyxj82rC2/4glIQ3TaYjoWfKykfVZ50A0
         h9XmCKrdz0CixzAWntIp1XSrI8MIDLHoNNVhns0u5bp1AZMmpJSDn23Dti36QXpc2HHe
         qc7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kNWxc7urAc+WPUb7dtJ1KQJNNzOu7ZjngdMJAMiDVCE=;
        fh=Y8mzEZx9Kk8nTmJnAVxPhtQ68ey4rxLFxnvpOEoqJr0=;
        b=CNLYdRiayu2BZXpve7ikyDQxCBYwY4VOTHh/g6k3hSbWgyI/Dr91cTs4nHRuogXLPN
         d63Udo/P2u5Eta21nwMp5EBV449ShwQX1+txRh+uWkTZRji6Ia7tWbzO1RCqG5SkVTgg
         NW7STuUiRbzFtDO7Ln7RffTGRtEV5zaaMksyqYMWfaNinvK0DWO4XgBd4DY9DLUZs5kb
         Eh+0lfku92cP6owZyGS4X/e49SoM4k7q+sVxvKp89/KgOsSnfrvDUKyhYB0SN8Ol/TeC
         +YaNJNfBDaZIssyB59t+m4J5Lo7BRDJvrfAbChlfAwOxCzuRVS97cUBZB/mdI0RfotNG
         fjEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XObCGkMj;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b75ec60desi329808e87.2.2026.01.13.11.16.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 11:16:01 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-382fb1e257bso9362081fa.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 11:16:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVc2ZzXG3YfGBG2l9jkskYl1eLgLjlGxcL7qj5IP8Rs437BgtrfvijQIbykQrV+BCyEIRxPIMr3tTY=@googlegroups.com
X-Gm-Gg: AY/fxX4msV1Wyw0AvAuSMceeqZ2vlaBxZUjpMBtd/XCVgHb0uyqro8swlCLqUCXjN5P
	SI1l+6TcXNVm9Dpp8M8nro1+q4heRIyGixBCOjg86kUnWGlntGj+FhjTwpp4uJ72YRXUoadofRZ
	QTAJcqvCFfoIShRT9vpDf0wIoHLkPNgwuQjMlFprS48p5lcX8B+u+dcN8khhWsN4bOmn0HznR/F
	sbxyySWzoBvII04FMQFLc7cLGZlBJ5szVYp85zI4rqGF2HQrtP+awXx73Ok5VAsATyHj/aHkCzM
	WpbVfdQ/7ASDbQAdS3EdnsrxeKY1m1AvR+w1kZk3oFkBHTSxS+OhC3NF8swcK+34tSTLkBCwNV3
	WYWVgrT5guXwqcZVoDxg5bgX68T2CIaHJQBWFtjgtNKpb3aaA/QcVQ8rYJO0gYq4QZh2qrhM7vZ
	cIgvmNFgCeHNXA4czMCbdDB1kuaz0IWXfgdA==
X-Received: by 2002:a05:6512:3b25:b0:59b:7291:9cd8 with SMTP id 2adb3069b0e04-59b72919e55mr4212248e87.7.1768331760373;
        Tue, 13 Jan 2026 11:16:00 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59b6a97e94csm5568773e87.91.2026.01.13.11.15.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 11:15:59 -0800 (PST)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: =?UTF-8?q?Maciej=20=C5=BBenczykowski?= <maze@google.com>,
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Uladzislau Rezki <urezki@gmail.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	joonki.min@samsung-slsi.corp-partner.google.com,
	stable@vger.kernel.org
Subject: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
Date: Tue, 13 Jan 2026 20:15:15 +0100
Message-ID: <20260113191516.31015-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XObCGkMj;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22c
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

A KASAN warning can be triggered when vrealloc() changes the requested
size to a value that is not aligned to KASAN_GRANULE_SIZE.

    ------------[ cut here ]------------
    WARNING: CPU: 2 PID: 1 at mm/kasan/shadow.c:174 kasan_unpoison+0x40/0x4=
8
    ...
    pc : kasan_unpoison+0x40/0x48
    lr : __kasan_unpoison_vmalloc+0x40/0x68
    Call trace:
     kasan_unpoison+0x40/0x48 (P)
     vrealloc_node_align_noprof+0x200/0x320
     bpf_patch_insn_data+0x90/0x2f0
     convert_ctx_accesses+0x8c0/0x1158
     bpf_check+0x1488/0x1900
     bpf_prog_load+0xd20/0x1258
     __sys_bpf+0x96c/0xdf0
     __arm64_sys_bpf+0x50/0xa0
     invoke_syscall+0x90/0x160

Introduce a dedicated kasan_vrealloc() helper that centralizes
KASAN handling for vmalloc reallocations. The helper accounts for KASAN
granule alignment when growing or shrinking an allocation and ensures
that partial granules are handled correctly.

Use this helper from vrealloc_node_align_noprof() to fix poisoning
logic.

Reported-by: Maciej =C5=BBenczykowski <maze@google.com>
Reported-by: <joonki.min@samsung-slsi.corp-partner.google.com>
Closes: https://lkml.kernel.org/r/CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08=
oLO3odYFrA@mail.gmail.com
Fixes: d699440f58ce ("mm: fix vrealloc()'s KASAN poisoning logic")
Cc: stable@vger.kernel.org
Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/shadow.c     | 24 ++++++++++++++++++++++++
 mm/vmalloc.c          |  7 ++-----
 3 files changed, 32 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9c6ac4b62eb9..ff27712dd3c8 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -641,6 +641,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int n=
r_vms,
 		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
 }
=20
+void kasan_vrealloc(const void *start, unsigned long old_size,
+		unsigned long new_size);
+
 #else /* CONFIG_KASAN_VMALLOC */
=20
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -670,6 +673,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int n=
r_vms,
 			  kasan_vmalloc_flags_t flags)
 { }
=20
+static inline void kasan_vrealloc(const void *start, unsigned long old_siz=
e,
+				unsigned long new_size) { }
+
 #endif /* CONFIG_KASAN_VMALLOC */
=20
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 32fbdf759ea2..e9b6b2d8e651 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -651,6 +651,30 @@ void __kasan_poison_vmalloc(const void *start, unsigne=
d long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
=20
+void kasan_vrealloc(const void *addr, unsigned long old_size,
+		unsigned long new_size)
+{
+	if (!kasan_enabled())
+		return;
+
+	if (new_size < old_size) {
+		kasan_poison_last_granule(addr, new_size);
+
+		new_size =3D round_up(new_size, KASAN_GRANULE_SIZE);
+		old_size =3D round_up(old_size, KASAN_GRANULE_SIZE);
+		if (new_size < old_size)
+			__kasan_poison_vmalloc(addr + new_size,
+					old_size - new_size);
+	} else if (new_size > old_size) {
+		old_size =3D round_down(old_size, KASAN_GRANULE_SIZE);
+		__kasan_unpoison_vmalloc(addr + old_size,
+					new_size - old_size,
+					KASAN_VMALLOC_PROT_NORMAL |
+					KASAN_VMALLOC_VM_ALLOC |
+					KASAN_VMALLOC_KEEP_TAG);
+	}
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
=20
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 41dd01e8430c..2536d34df058 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4322,7 +4322,7 @@ void *vrealloc_node_align_noprof(const void *p, size_=
t size, unsigned long align
 		if (want_init_on_free() || want_init_on_alloc(flags))
 			memset((void *)p + size, 0, old_size - size);
 		vm->requested_size =3D size;
-		kasan_poison_vmalloc(p + size, old_size - size);
+		kasan_vrealloc(p, old_size, size);
 		return (void *)p;
 	}
=20
@@ -4330,16 +4330,13 @@ void *vrealloc_node_align_noprof(const void *p, siz=
e_t size, unsigned long align
 	 * We already have the bytes available in the allocation; use them.
 	 */
 	if (size <=3D alloced_size) {
-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL |
-				       KASAN_VMALLOC_VM_ALLOC |
-				       KASAN_VMALLOC_KEEP_TAG);
 		/*
 		 * No need to zero memory here, as unused memory will have
 		 * already been zeroed at initial allocation time or during
 		 * realloc shrink time.
 		 */
 		vm->requested_size =3D size;
+		kasan_vrealloc(p, old_size, size);
 		return (void *)p;
 	}
=20
--=20
2.52.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0260113191516.31015-1-ryabinin.a.a%40gmail.com.
