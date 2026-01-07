Return-Path: <kasan-dev+bncBC7M7IOXQAGRBVVM7PFAMGQEAXKUXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E912D00409
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 22:55:36 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-78d6b5d45besf22701527b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 13:55:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767822935; cv=pass;
        d=google.com; s=arc-20240605;
        b=TiMdBlG1ZKGOgJb1TSYIUjCc/Ff53V03uYKnCzpffhvZn4pJohrX13ZEBve4dm9h8+
         lIHkeD1t6tggZwXdXaqN3CKFIXPAZ55YTGHkUhZtVA+2p6GbSw8Kuls1+E8FZhQMy6Ka
         QwYHIClzz5lwxq50HltCFclIXXj1YHKJMm6jaV0eqwwBrpmwaRdmSQ9sHhzZB/LpfODL
         sLfJ4WnZxa0SLDRFmF1q7sUMcqSxFubAvY8ZvGD2E8JuO7reNmkj36JqBQXbTAdGDfp2
         LBw8lU4EmImsHG7OVmMoekOUUi9GknETz1CaLnzoCPi46qU3mg3AaXhk9MmyHTN2gjWx
         J1ng==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P06BYZ99J66aHL7d0kNTxyfX5kOZWdSalhDuJ97GgGg=;
        fh=BMDKnPCzKx3DYpvNiPc1bYxl/ui+5jk3v1q/D6fjVFw=;
        b=ike/+5pNBegftXUcmrq41cvahOQBYXKH1SGdxfDKAhZRWEtHUcD16y7tj6OZ8hRKp4
         9Q8nPA3S3YVO1XUWKc9YIo0g0751RjuVyURRYQ2QXgcKYHph5/BrDvj1PJOY43V/xfC9
         GOfp3MGOU9iP11Ge8yVzvn1XBDl4YmdNLW9kVqv31eWW+HSRhASMED1GQzt82U6nSe86
         Y8NLTEfSoOLyDB3B7KsJFB75LsenzrWTAEl8t2BfqJUPSa2hVDDohOEkblWQXFQgtS2W
         c00/tCa+vE+INB9GoJvH4NEoSg0lb2kJZIkpsVIdGOhocfKQuz255q0SZQhZCLFmrQGV
         W4hQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KfX4UocU;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767822935; x=1768427735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P06BYZ99J66aHL7d0kNTxyfX5kOZWdSalhDuJ97GgGg=;
        b=PvoPNXTjt9YCoKsEsmjLkCd/Gc1mjFmlgbTjUVKbgBaLFcFKCOF7UkvVGOLWj0mk4q
         cOO9Ch6U1daWoXx9EG1ZW82gHSQ/gpJC88S37alJ7sIb0XBttezcaoykjBS6NSO3fe5r
         6hL5IoxeEHf5NKH7c05+6Z04VjD4Mk3Fc7e/jsEGOGtqLDlkXxF0ERLR/X08e/E6YIvn
         rPmd/503804YB3i/4KCj/JnXNV9sLPXQIFmnE5/opQZ4+UfQJq7294vsLBTETGVpS2DC
         n/ujoFZ/PnqJEI6yIQtlmRgoDJLs5miL0A6bakKWSU7iqTpVf2+EDyN1lqiEISHAf2Qe
         1Qmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767822935; x=1768427735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P06BYZ99J66aHL7d0kNTxyfX5kOZWdSalhDuJ97GgGg=;
        b=ldnlO3ab9HWK8xemh7T8E+4ppUSxnwDIJqb5gjiw91AUw4izZpwu6Kf49g8ptwSJA8
         jrB5WZz4r4cU5FQoPDjtIEFLbAs09UuL+vyK8SW1XVYGosh8/S9xG3WsyIk7Fm2xF6Rn
         IjedaD3AuaehvIhOfdMfRffX/8Z2eOhp0/e+oi75087AI0Y4vWWHJffRCrp4p0PGSXu4
         fy32rU35G1d1eu501r7A+MgZ0g0arGd57qINpr0zT2W0ueRQaELGyZ3cHsDBxMREjYiL
         KQvmSa8QrR5Bi1I0pA4IaaYRMSvwS8jHegwdcgq4wwivpxz1Xe3mlTMAPv2URfNSxusf
         /ksQ==
X-Forwarded-Encrypted: i=3; AJvYcCVvzzdvui2RorJFfNOOQ/vV8gNVT3O8Qh+fuGWkaVGNy6pvrItgV2hyl5KJc9pCKC2SsKX6sw==@lfdr.de
X-Gm-Message-State: AOJu0YynJje7eVKHX76bYUzpMOeobHLZPy/04HOONg0s8sdPrXBEOqDp
	uiEqRwfRsP8+EI6bm6disuixh+g/fVAHJlOjGi1j92UMeYwwi7iWv6a+
X-Google-Smtp-Source: AGHT+IG0HfVxxMmgSjlmQzTNIqsRV1JHdmDNsZ6IERQu/Tjb1t1xmN/bMEMzLY05fuItqbL7fnfyYQ==
X-Received: by 2002:a05:690e:b4b:b0:63f:a6e9:4048 with SMTP id 956f58d0204a3-6471674bfbcmr3216018d50.26.1767822935180;
        Wed, 07 Jan 2026 13:55:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWagRB2rKGWxH7ti3ZSqP/GVzTuD69AHSmB2LjaQfjjBuA=="
Received: by 2002:a05:690e:15d7:b0:63c:bedd:3afa with SMTP id
 956f58d0204a3-64716bd8435ls526253d50.2.-pod-prod-00-us; Wed, 07 Jan 2026
 13:55:34 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUpcp3v7OAufdv2EutlMgNZtn06N3n/4y8bJ52AAb4m+n++Sdeo1OrWdw1rjt9h09lEJ/9l3Gn6OJE=@googlegroups.com
X-Received: by 2002:a05:690e:13c8:b0:641:f5bc:692f with SMTP id 956f58d0204a3-6470d308713mr6082805d50.40.1767822934294;
        Wed, 07 Jan 2026 13:55:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767822934; cv=pass;
        d=google.com; s=arc-20240605;
        b=G1OPgZNQ+IG4wW0j+Mxdo80V1XhE6WJ6T8uCM3nWgY+ZW330cIrQaAwgdcKWy1whfO
         IHuTqU+Z5CwrjWVlzmP16yvgvTamI6YLmr8SQWb7MQwxHFFcNcUb2AhGVI7WydUTMQbJ
         Eir713Rhw8wgbxWrKDq1Ilj1Ur6TddJqSa/ZjfM1TZDyngiMynDEvbXxWp8iK2/48xCC
         73ujI2lLJh1dtUuw+4pNfZ0GA8nCRgPW72qF/g1i0igQLNVyodgFBhB40onZbqO5NrsS
         Fse3NxOclwe1aEC38AK/7ejciwHFcgPL+4bwcTCLn/AHh3JvlMf0QghyxCCoTHfsvYKj
         iu2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6fRI8t9Yow/e3W/odLxxmoc1WYobO0D4rJNJUIXQBJM=;
        fh=9EuGVNb5XQ/TfUwwaC4VA6XdV4A1pTqGADvYmiCGj7E=;
        b=dJtCotxBw4jph3+HAQRRCWbqdkNKZOXvKPYBr+CqaXx+p/1EuT9ugFqoM2KYnT9uhj
         7BuovwPbAl++fNFVqwQf8DpTzRR4wk/AyXmXBlOh4rJrnojJQqfiToahDHZfvAsmuhSz
         AAnXhdvbdcPqOZH6JlXxW6U3T1RMZ0p7stQOEAvSE8SizHI6e45BEzOVUazwZxFFbaxi
         2tzhgSNedI0v7jb0IFN1bmQQ9Ma1r1JOma6RimrFveTHi2icRJIrvkztOK0Q+HBsCNsw
         t/r21e+fkVicRJDK0vlLd3nI2TVPvL3DH1vvamAckwom74l/KE8A+avci+ZIg/qgkBlW
         kpmg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KfX4UocU;
       arc=pass (i=1);
       spf=pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-790aab96520si1171957b3.7.2026.01.07.13.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Jan 2026 13:55:34 -0800 (PST)
Received-SPF: pass (google.com: domain of maze@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id d75a77b69052e-4ee243b98caso535331cf.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Jan 2026 13:55:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767822934; cv=none;
        d=google.com; s=arc-20240605;
        b=krbkQaOulPuFEFZnTX8TGj9SN1appTChNAN3NxB0Ux400PtuTKG7uhaFR0zBSgc2Tr
         OHp6rkfzW83cdA6sA1t6lq+JouCf2D/D4ulmQoeUCeSsLIWjo4Ef2oeOX8a5yCdbZS3r
         fpIXC7ANCb+HlTBA1xlJljFIrCb/aux0WhvufFxRHeQbVjdumZaPKcsLNLOakQwcF9DY
         BLLctjRS+vdOrRQ4i4xHgVI3+hxvtRe0TZkIGWgA8BX5twfvABn0DWbDBN0I7pBciDdo
         vPPhlfOT1z2gB+Nh9ZnvmSzX2xNI1W7iLoJQkoHC+yJNlBJ/H4n4XhrP1LGWZxe5BjUR
         Sz8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6fRI8t9Yow/e3W/odLxxmoc1WYobO0D4rJNJUIXQBJM=;
        fh=9EuGVNb5XQ/TfUwwaC4VA6XdV4A1pTqGADvYmiCGj7E=;
        b=bGHSFff0cQ5/sJEytqk7gIr44qRD4/6VnEm2h6rEDRgt/bC07c9Gd9G/90ad5zaPKk
         ijtGO1qAc9/oT11+9uQ5wBFwBCuANQa6bX8Xd09qrMbdH22jxG45XC0B4ibjlPb+Gp1H
         miFNk4A/uCJ2Bkdv4LScKkErupGajrJHTYc6iLuEhh9eVTR9j0rBGayUPuq6vbzNFWyn
         GeGBwATyy81gvBiJx2xMW+aSBOavdtCib3IWUAqFRvyb7uDD4a/8TxfRrCxe3KUCRmaM
         cW+jhiVF3eDhqGT5Lwm2D3w5/s1RVj5UFKRURC7GKoMBzHkeR5EK+KP7+wH7rNwHiBWD
         Jjmg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCW5FDc+Ml459FGvlGfivXZZ9syMoEZKBYotyl3SlbcQIf9VPjE4Esr88/WQBOp8owawVv5oFQ7LxS8=@googlegroups.com
X-Gm-Gg: AY/fxX4ZN6x6thMXnrWPZmavOf0l862Bhh+Hc1Pvu1Vp/KizDSN8pWPAmwHMQ+4T6dv
	VLm0U1yGaUlC9j1zx7+kE/3V94451DoPSA0/C98/vscV7259Nd2ANr1phgdMxUXuYNJaP+TwCiH
	15cY92dB1mIsTf8C+TNasdWIvK5Kdc9bZQvo2/L0tPnxGrumRjhl5wbyYHAMcLRO2Zj+wVq9iLJ
	zAwkWunzN2vjLpRgyFu717AJRSKN4ZaK6z3aptFVYjIn0SSyHVOPjjWrg+OX19YoQCMb5Uwyxpv
	63uzbhcRbgTzsOh/jAXTr3QaLyNG
X-Received: by 2002:ac8:57cb:0:b0:4ff:a98b:7fd3 with SMTP id
 d75a77b69052e-4ffc091f255mr623981cf.2.1767822933523; Wed, 07 Jan 2026
 13:55:33 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt>
 <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com> <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
In-Reply-To: <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com>
From: =?UTF-8?Q?=27Maciej_=C5=BBenczykowski=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Date: Wed, 7 Jan 2026 22:55:21 +0100
X-Gm-Features: AQt7F2oohXGQVvxlmT23b9Uc5zteHdRxxTlRoo--luOtr2cVC6ZeMOEtT_AqGzY
Message-ID: <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com>
Subject: Re: KASAN vs realloc
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, 
	Andrew Morton <akpm@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: maze@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KfX4UocU;       arc=pass
 (i=1);       spf=pass (google.com: domain of maze@google.com designates
 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=maze@google.com;
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

> WARNING: Actually I'm not sure if this is the *right* stack trace.
> This might be on a bare 6.18 without the latest extra 4 patches.
> I'm not finding a more recent stack trace.

Found comments from Samsung dev:

But another panic came after those fixes [ie. 4 patches] applied.
struct bpf_insn_aux_data is 88byte, so panic on warn set when old_size
ends with 0x8.
It seems like vrealloc cannot handle that case.

  84.536021] [4:     netbpfload:  771] ------------[ cut here ]------------
[   84.536196] [4:     netbpfload:  771] WARNING: CPU: 4 PID: 771 at
mm/kasan/shadow.c:174 __kasan_unpoison_vmalloc+0x94/0xa0
....
[   84.773445] [4:     netbpfload:  771] CPU: 4 UID: 0 PID: 771 Comm:
netbpfload Tainted: G           OE
6.18.1-android17-0-g41be44edb8d5-4k #1 PREEMPT
70442b615e7d1d560808f482eb5d71810120225e
[   84.789323] [4:     netbpfload:  771] Tainted: [O]=OOT_MODULE,
[E]=UNSIGNED_MODULE
[   84.795311] [4:     netbpfload:  771] Hardware name: Samsung xxxx
[   84.802519] [4:     netbpfload:  771] pstate: 03402005 (nzcv daif
+PAN -UAO +TCO +DIT -SSBS BTYPE=--)
[   84.810152] [4:     netbpfload:  771] pc : __kasan_unpoison_vmalloc+0x94/0xa0
[   84.815708] [4:     netbpfload:  771] lr : __kasan_unpoison_vmalloc+0x24/0xa0
[   84.821264] [4:     netbpfload:  771] sp : ffffffc0a97e77a0
[   84.825256] [4:     netbpfload:  771] x29: ffffffc0a97e77a0 x28:
3bffff8837198670 x27: 0000000000008000
[   84.833069] [4:     netbpfload:  771] x26: 41ffff8837ef8e00 x25:
ffffffffffffffa8 x24: 00000000000071c8
[   84.840880] [4:     netbpfload:  771] x23: 0000000000000001 x22:
00000000ffffffff x21: 000000000000000e
[   84.848694] [4:     netbpfload:  771] x20: 0000000000000058 x19:
c3ffffc0a8f271c8 x18: ffffffc082f1c100
[   84.856504] [4:     netbpfload:  771] x17: 000000003688d116 x16:
000000003688d116 x15: ffffff8837efff80
[   84.864317] [4:     netbpfload:  771] x14: 0000000000000180 x13:
0000000000000000 x12: e6ffff8837eff700
[   84.872129] [4:     netbpfload:  771] x11: 0000000000000041 x10:
0000000000000000 x9 : fffffffebf800000
[   84.879941] [4:     netbpfload:  771] x8 : ffffffc0a8f271c8 x7 :
0000000000000000 x6 : ffffffc0805bef3c
[   84.887754] [4:     netbpfload:  771] x5 : 0000000000000000 x4 :
0000000000000000 x3 : ffffffc080234b6c
[   84.895566] [4:     netbpfload:  771] x2 : 000000000000000e x1 :
0000000000000058 x0 : 0000000000000001
[   84.903377] [4:     netbpfload:  771] Call trace:
[   84.906502] [4:     netbpfload:  771]  __kasan_unpoison_vmalloc+0x94/0xa0 (P)
[   84.912058] [4:     netbpfload:  771]  vrealloc_node_align_noprof+0xdc/0x2e4
[   84.917525] [4:     netbpfload:  771]  bpf_patch_insn_data+0xb0/0x378
[   84.922384] [4:     netbpfload:  771]  bpf_check+0x25a4/0x8ef0
[   84.926638] [4:     netbpfload:  771]  bpf_prog_load+0x8dc/0x990
[   84.931065] [4:     netbpfload:  771]  __sys_bpf+0x340/0x524

[   79.334574][  T827] bpf_patch_insn_data: insn_aux_data size realloc
at abffffc08ef41000 to 330
[   79.334919][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00000

[   79.335151][  T827] bpf_patch_insn_data: insn_aux_data size realloc
at 55ffffc0a9c00000 to 331
[   79.336331][  T827] vrealloc_node_align_noprof: p=55ffffc0a9c00000
old_size=7170
[   79.343898][  T827] vrealloc_node_align_noprof: size=71c8 alloced_size=8000
[   79.350782][  T827] bpf_patch_insn_data: insn_aux_data at 55ffffc0a9c00000

[   79.357591][  T827] bpf_patch_insn_data: insn_aux_data size realloc
at 55ffffc0a9c00000 to 332
[   79.366174][  T827] vrealloc_node_align_noprof: p=55ffffc0a9c00000
old_size=71c8
[   79.373588][  T827] vrealloc_node_align_noprof: size=7220 alloced_size=8000
[   79.380485][  T827] kasan_unpoison: after kasan_reset_tag
addr=ffffffc0a9c071c8(granule mask=f)

I added 8 bytes dummy data to avoid "p + old_size" was not ended with
8, it booted well.

diff --git a/include/linux/bpf_verifier.h b/include/linux/bpf_verifier.h
index 4c497e839526..f9d3448321e8 100644
--- a/include/linux/bpf_verifier.h
+++ b/include/linux/bpf_verifier.h
@@ -581,6 +581,7 @@ struct bpf_insn_aux_data {
        u32 scc;
        /* registers alive before this instruction. */
        u16 live_regs_before;
+       u16 buf[4];     // TEST
 };

maze: Likely if 8 bytes worked then 'u8 buf[7]' would too?

it will be 88bytes + 7 bytes = 95 bytes(=0x5f) which is in the range
of granule mask(=0xf)

I don't think it works, but it works.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf%2B4wHpnSwRX4M8bLDW9g%40mail.gmail.com.
