Return-Path: <kasan-dev+bncBDW2JDUY5AORBJO46HCQMGQE23GWYZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id DEE0EB475CE
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:23:51 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-336b13923d4sf15760391fa.1
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:23:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179431; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPYq2J2zD9if3kPYHwrVmWDS3CiFPkqPSxF3R0cegR5F0TvlTw/nbLpuoEGTb3GjtG
         KHBlJ/gYfDb0lZSpiU0XjkSI6MtrIPv05K40lzLIIrMJDVGJDRA+OyrEL8zwmLb/sqwR
         dEJKgWsA9Y3495jtgLJxuss8pvsT8J+Pg5BYUO/EKuTNCfBLd1k87CeFq0xX7J6Epi+1
         lakx6OcbP9rE2zumH7a6dNcF3DVlVgIoCCWiFnC/OfvjuWPtmrGER5YqOv/hjpq4YtS2
         qBR6/XPFWZaypxNl1RHxbxN2571dXrL5rzQFT2/wbGJTnOUZXzCJg0Rgb+nLZrwPr8eB
         fBzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OUYy5WV7/SlaA7z0c5v7dUXfqoktrw5vp83CUjoDDbg=;
        fh=sXN/m8Rnhz3Fm6Q8mHfE4vuPB7uJDLXKYpneXTiip/E=;
        b=ALkxGioGV/Xn/y2SxMOs93Pyop7D24nMqM8hCkgxoAHkTvifp+OfTyDeiwZfhsClhm
         M7M9tg8+u8McbGEhYzf8LdeKf9yBapjk6h8ekkH5SC0K0gX8gtzUXESQ32xesx1JZa91
         rpVH1epM5IOLTwLzJ6Zfa7iikg/NxJTNECTjBSMgGyjdgFv0sIMItOwX36M+jUE+nPED
         cEswvuoTMIz9pMAI/CFfe3XWx5L0ibVULmKAHuvwVjrKXGf/OLRLuVH5XDYIbCWWtBDJ
         hx8gCaQrVUUo9OMfPBlg5h3x2mgVx1nCulZ8x0QzfBCthtcjkotnX2m84ewsZp2TzysF
         FZ/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QybubthW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179431; x=1757784231; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OUYy5WV7/SlaA7z0c5v7dUXfqoktrw5vp83CUjoDDbg=;
        b=mV7HCiOQvuehkFGZHk9OnAlo5cjZhMEBfQ7u/KvE8FGWI9N/1rTNSDKK6AoWpCCRKt
         w+2rCFfgRTCvt0jyMkoeVeyASL3nYfdDtkwfGdL8AgmSYaqcubw5DgCxuzvnzh+raYp7
         UKxW0/tNqppCuNP+xVZkObdNC8k0zqzUWY9tizXyX0nKsTmieFq01OzdMhZgbzlOWklD
         Zj7riW9D9wTbnTpa+7/nowpKAht4kqVx1s4MsDOpgvSeQ2bPj+fw/d6Yy1FTZzQY8ZgS
         +GlK0FZDXXM4aIuNGhQBoXwp+2h+F4BD+E6nrftREjduZsTX61n4dSbUbm4MOXXimUNV
         Zaqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179431; x=1757784231; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OUYy5WV7/SlaA7z0c5v7dUXfqoktrw5vp83CUjoDDbg=;
        b=RoS4TAvPoLwkFeyeKUOglWGxXPvxNaIU4/iEitU+LhkOTQebxcWfIPJJoye71CFgtY
         Em0xIQgbRWkEzIakZB1y6WEsmiWUHTq4h42TwkrWBdVSanD+IlhmwhpHJn7HhFuRjk7p
         z08SJVSJPipRz2d2MqGxfzPXbYQvXebvWIKurr5gsJ1Td+M1eVrCxAdbMOQY+EqsAYBb
         imNpjUVmA+OsJKDY/EJWE6qaZpqjm4V/qaSds1+WfAHfiwkvo3so2UFaUgnnQ/U5XAGU
         SLSNW+KNVZX1YfQJp2CxdwbXmyMpiQ/UX3qOvSwaCr87tvIM64kQOfJ5BNTAwGZaE6fQ
         tX1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179431; x=1757784231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OUYy5WV7/SlaA7z0c5v7dUXfqoktrw5vp83CUjoDDbg=;
        b=po2ggM026mj0XtI76mxV+sIiMuvRtDogyaq/zBqKBazOjxQZdjMk6zy3YPRtwvFahU
         C1qdkXpNq43udv/0LPaomHx/uoM80JhUTskTgBmNXYrBoU+XK6Kv4Wli3ohGcl9NypSA
         9tYl637k61ZokuxEZys4Oie2G8BZIS+lrPfe3qmcXi/85HWfxW1DKJH7gAo++zcfyCdh
         O2+jLHAnFd4HMO/rqntgIrf0MAqYiHf6tYdJ5bP9WIg7INoGOIdFIbiYx2/3S8CSSllg
         j1hY1SrIFxbVJBBT/VGfGxIviufIUCxKftFXfycrCojTJM4jMpqxgKIkSNguDzY5e5Wo
         6f2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1WkvV6nK+8ssZn4LS6E3MXsd4eKk7RcNHioexaTWSVa2Vac2+xF3u0n6BXxW2st8uhLqFaA==@lfdr.de
X-Gm-Message-State: AOJu0YzBCGzmfbE2FarFhZBYqFBvuPbnQj4jCfwyf5B+gAaP+N5mGI/F
	SrtxOcK0Xx7eTKVsuDjgDyjqCfZ7EE6pE9SoLlGGQiuY4XdBIK5ix2Fd
X-Google-Smtp-Source: AGHT+IGmSP73rEyKXON5jqlczatMjXdzVAl84twqg+mdNd6hYA0AqYKJ3QMl51xhhgo9p2/TttRmhw==
X-Received: by 2002:a05:651c:1696:b0:336:6c93:9726 with SMTP id 38308e7fff4ca-33b50ac79a5mr4633351fa.4.1757179430393;
        Sat, 06 Sep 2025 10:23:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeWAuBb/hqZVGZOonkgHCyb2kPrLPy2sSrTBovOCUk8hg==
Received: by 2002:a2e:a375:0:b0:337:e84b:ebd with SMTP id 38308e7fff4ca-338cd23e47fls4126071fa.0.-pod-prod-07-eu;
 Sat, 06 Sep 2025 10:23:47 -0700 (PDT)
X-Received: by 2002:a05:651c:4117:b0:336:c6bb:10dc with SMTP id 38308e7fff4ca-33b526a8801mr4323071fa.17.1757179427677;
        Sat, 06 Sep 2025 10:23:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179427; cv=none;
        d=google.com; s=arc-20240605;
        b=KEVCnFh02uvuD1dKC3Bmt0o+qzZ+6/69Aw8hezq6LlpSQrlBNDO+ya99adwz7JpNAk
         fK4RI9Y0Ua1ReItYUyq2ag8OqfIYtgn7uJ2DAr/P8KP19HNMmYhW/N8HA4Mt2zV+a+Sl
         CyHDNQoDuiG72KZvMhxZMUaqR/R1+BPzhcV2JSOfYQcV9ghlU35sVVwQfp53tXVCYyEP
         LAd/iDyK/VLmrIR91BLGN8Mjingy9suiftZwKAjtIQ9Kh8l1tU0LXKdFPKIqul0GjyE0
         DL5uArXcq63J7Trc9+yPqs+ojWT1NHtmwl22QkpQZlOr12fMKkm1eXhZe6sWofAi6kCS
         e7bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4c2O+YGbvDnPu9AoMwBBiCr1o4ZEGNWgiuTpwDevAek=;
        fh=6YCovQoYDiAxkRL/X78L4cxoxYdwR0lfNHm5Lmguo9k=;
        b=lWw7tR0V58s9lrsr8On6icChqbsRI3evdvshTXZ/FBxBJeU8LaoWyC8Wm26Ck8knOW
         B9n0NyDeAJImuQ7ElAjrxNL7GxTA1eezkW88ATDMG5wQ8ZZfTX/5TIR+Q4LxWE1UcliN
         V5fYnAsw5LaG+Vh9tnUK/+UnSdDqzvDb0Lfm55iT/5cJVW1NYxq/dQKgrKCm1Cv2Pv95
         hrWGPIulrE5IVGyXhvQSgi/YhLBWBu/LIjQaJgAGdcuylyt2zQju/+ZuPxtZsBQpedJP
         oynBiSploCnaxaFtes7XHbClJFieL0YBKa+FWvEJ3/spZ9tBnSGZSMbD/EwuxxLZyuo/
         cUrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QybubthW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4fd35b9si2845861fa.6.2025.09.06.10.23.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:23:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-45ddcf50e95so7258425e9.0
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:23:47 -0700 (PDT)
X-Gm-Gg: ASbGncv8Me0muvLK32egl1XCMlXBHn5Y9qsIcX9OtoomRXDiLgGJhaeU1saj4HWNtHN
	mqIsreYl+20ZYt+ZyQt7COvc5N+o5T3PmsRcrbsSL2BEN0WLt8Xu9r3z04cyYeLwdri0rl8emDJ
	UK9alzLC5tVMA/tQlpiY/w2Byg/z+xM2zAD2ZHYekck1+C1avrwR82cDwOu5Mld7IC5uYBzeXr9
	kxQNKJS
X-Received: by 2002:a05:600c:19ce:b0:45b:b05a:aeeb with SMTP id
 5b1f17b1804b1-45dddec8ff1mr22462305e9.28.1757179426824; Sat, 06 Sep 2025
 10:23:46 -0700 (PDT)
MIME-Version: 1.0
References: <aKMLgHdTOEf9B92E@MiWiFi-R3L-srv>
In-Reply-To: <aKMLgHdTOEf9B92E@MiWiFi-R3L-srv>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:23:36 +0200
X-Gm-Features: AS18NWBaEWkn9-xRc9TLHpIVSI5D7m1H84UghxFJ-i2_WVGQHVzaNNUWikgWzvg
Message-ID: <CA+fCnZebyMgWWEOW_ZxiGwnkiXqXX6XK5NJv-uWXAxdN+JxsSw@mail.gmail.com>
Subject: Re: System is broken in KASAN sw_tags mode during bootup
To: Baoquan He <bhe@redhat.com>
Cc: kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-mm@kvack.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QybubthW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
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

On Mon, Aug 18, 2025 at 1:16=E2=80=AFPM Baoquan He <bhe@redhat.com> wrote:
>
> Hi,
>
> This can be reproduced stably on hpe-apollo arm64 system with the latest
> upstream kernel. I have this system at hand now, the boot log and kernel
> config are attached for reference.
>
> [   89.257633] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   89.257646] BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a=
8
> [   89.257672] Write of size 528 at addr ddfffd7fbdc00000 by task systemd=
/1
> [   89.257685] Pointer tag: [dd], memory tag: [ca]
> [   89.257692]
> [   89.257703] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc=
2 #1 PREEMPT(voluntary)
> [   89.257719] Hardware name: HPE Apollo 70             /C01_APACHE_MB   =
      , BIOS L50_5.13_1.16 07/29/2020
> [   89.257726] Call trace:
> [   89.257731]  show_stack+0x30/0x90 (C)
> [   89.257753]  dump_stack_lvl+0x7c/0xa0
> [   89.257769]  print_address_description.isra.0+0x90/0x2b8
> [   89.257789]  print_report+0x120/0x208
> [   89.257804]  kasan_report+0xc8/0x110
> [   89.257823]  kasan_check_range+0x7c/0xa0
> [   89.257835]  __asan_memset+0x30/0x68
> [   89.257847]  pcpu_alloc_noprof+0x42c/0x9a8
> [   89.257859]  mem_cgroup_alloc+0x2bc/0x560
> [   89.257873]  mem_cgroup_css_alloc+0x78/0x780
> [   89.257893]  cgroup_apply_control_enable+0x230/0x578
> [   89.257914]  cgroup_mkdir+0xf0/0x330
> [   89.257928]  kernfs_iop_mkdir+0xb0/0x120
> [   89.257947]  vfs_mkdir+0x250/0x380
> [   89.257965]  do_mkdirat+0x254/0x298
> [   89.257979]  __arm64_sys_mkdirat+0x80/0xc0
> [   89.257994]  invoke_syscall.constprop.0+0x88/0x148
> [   89.258011]  el0_svc_common.constprop.0+0x78/0x148
> [   89.258025]  do_el0_svc+0x38/0x50
> [   89.258037]  el0_svc+0x3c/0x168
> [   89.258050]  el0t_64_sync_handler+0xa0/0xf0
> [   89.258063]  el0t_64_sync+0x1b0/0x1b8
> [   89.258076]
> [   89.258080] The buggy address belongs to a 0-page vmalloc region start=
ing at 0xcafffd7fbdc00000 allocated at pcpu_get_vm_areas+0x0/0x1da0
> [   89.258111] The buggy address belongs to the physical page:
> [   89.258117] page: refcount:1 mapcount:0 mapping:0000000000000000 index=
:0x0 pfn:0x881ddac
> [   89.258129] flags: 0xa5c00000000000(node=3D1|zone=3D2|kasantag=3D0x5c)
> [   89.258148] raw: 00a5c00000000000 0000000000000000 dead000000000122 00=
00000000000000
> [   89.258160] raw: 0000000000000000 f3ff000813efa600 00000001ffffffff 00=
00000000000000
> [   89.258168] raw: 00000000000fffff 0000000000000000
> [   89.258173] page dumped because: kasan: bad access detected
> [   89.258178]
> [   89.258181] Memory state around the buggy address:
> [   89.258192] Unable to handle kernel paging request at virtual address =
ffff7fd7fbdbffe0
> [   89.258199] KASAN: probably wild-memory-access in range [0xfffffd7fbdb=
ffe00-0xfffffd7fbdbffe0f]
> [   89.258207] Mem abort info:
> [   89.258211]   ESR =3D 0x0000000096000007
> [   89.258216]   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
> [   89.258223]   SET =3D 0, FnV =3D 0
> [   89.258228]   EA =3D 0, S1PTW =3D 0
> [   89.258232]   FSC =3D 0x07: level 3 translation fault
> [   89.258238] Data abort info:
> [   89.258241]   ISV =3D 0, ISS =3D 0x00000007, ISS2 =3D 0x00000000
> [   89.258246]   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
> [   89.258252]   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0
> [   89.258260] swapper pgtable: 4k pages, 48-bit VAs, pgdp=3D0000008ff8b8=
f000
> [   89.258267] [ffff7fd7fbdbffe0] pgd=3D1000008ff0275403, p4d=3D1000008ff=
0275403, pud=3D1000008ff0274403, pmd=3D1000000899079403, pte=3D000000000000=
0000
> [   89.258296] Internal error: Oops: 0000000096000007 [#1]  SMP
> [   89.540859] Modules linked in: i2c_dev
> [   89.544619] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-rc=
2 #1 PREEMPT(voluntary)
> [   89.553234] Hardware name: HPE Apollo 70             /C01_APACHE_MB   =
      , BIOS L50_5.13_1.16 07/29/2020
> [   89.562970] pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
> [   89.569933] pc : __pi_memcpy_generic+0x24/0x230
> [   89.574472] lr : kasan_metadata_fetch_row+0x20/0x30
> [   89.579350] sp : ffff8000859d76c0
> [   89.582660] x29: ffff8000859d76c0 x28: 0000000000000100 x27: ffff008ec=
626d800
> [   89.589807] x26: 0000000000000210 x25: 0000000000000000 x24: fffffd7fb=
dbfff00
> [   89.596952] x23: ffff8000826cbeb8 x22: fffffd7fbdc00000 x21: 00000000f=
ffffffe
> [   89.604097] x20: ffff800082682ee0 x19: fffffd7fbdbffe00 x18: 000000000=
49016ff
> [   89.611242] x17: 3030303030303030 x16: 2066666666666666 x15: 663130303=
0303030
> [   89.618386] x14: 0000000000000001 x13: 0000000000000001 x12: 000000000=
0000001
> [   89.625530] x11: 687420646e756f72 x10: 0000000000000020 x9 : 000000000=
0000000
> [   89.632674] x8 : ffff78000859d766 x7 : 0000000000000000 x6 : 000000000=
000003a
> [   89.639818] x5 : ffff8000859d7728 x4 : ffff7fd7fbdbfff0 x3 : efff80000=
0000000
> [   89.646963] x2 : 0000000000000010 x1 : ffff7fd7fbdbffe0 x0 : ffff80008=
59d7718
> [   89.654107] Call trace:
> [   89.656549]  __pi_memcpy_generic+0x24/0x230 (P)
> [   89.661086]  print_report+0x180/0x208
> [   89.664753]  kasan_report+0xc8/0x110
> [   89.668333]  kasan_check_range+0x7c/0xa0
> [   89.672258]  __asan_memset+0x30/0x68
> [   89.675836]  pcpu_alloc_noprof+0x42c/0x9a8
> [   89.679935]  mem_cgroup_alloc+0x2bc/0x560
> [   89.683947]  mem_cgroup_css_alloc+0x78/0x780
> [   89.688222]  cgroup_apply_control_enable+0x230/0x578
> [   89.693191]  cgroup_mkdir+0xf0/0x330
> [   89.696771]  kernfs_iop_mkdir+0xb0/0x120
> [   89.700697]  vfs_mkdir+0x250/0x380
> [   89.704103]  do_mkdirat+0x254/0x298
> [   89.707596]  __arm64_sys_mkdirat+0x80/0xc0
> [   89.711697]  invoke_syscall.constprop.0+0x88/0x148
> [   89.716491]  el0_svc_common.constprop.0+0x78/0x148
> [   89.721286]  do_el0_svc+0x38/0x50
> [   89.724602]  el0_svc+0x3c/0x168
> [   89.727746]  el0t_64_sync_handler+0xa0/0xf0
> [   89.731933]  el0t_64_sync+0x1b0/0x1b8
> [   89.735603] Code: f100805f 540003c8 f100405f 540000c3 (a9401c26)
> [   89.741695] ---[ end trace 0000000000000000 ]---
> [   89.746308] note: systemd[1] exi
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D

Might be the same issue as the one being fixed by Maciej here:

https://lore.kernel.org/all/bcf18f220ef3b40e02f489fdb90fc7a5a153a383.175615=
1769.git.maciej.wieczor-retman@intel.com/
https://lore.kernel.org/all/3339d11e69c9127108fe8ef80a069b7b3bb07175.175615=
1769.git.maciej.wieczor-retman@intel.com/

Perhaps it makes sense to split that fix out of the series and submit
separately.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZebyMgWWEOW_ZxiGwnkiXqXX6XK5NJv-uWXAxdN%2BJxsSw%40mail.gmail.com.
