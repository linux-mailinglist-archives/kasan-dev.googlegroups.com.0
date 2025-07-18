Return-Path: <kasan-dev+bncBCMJ3Y5474BBBKVD5DBQMGQEIGZBTVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 80146B09F19
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 11:19:40 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7e2e8a90a90sf270463885a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 02:19:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752830379; cv=pass;
        d=google.com; s=arc-20240605;
        b=IfRdxnAFvhxcAqcq1l0GlgReWDDl97pmN1QK42/qpx+3nLvReCDm9C7Bu2gtGgxObG
         i354gFd6sF+Bcaanjhqcv3DGhutbEy3scEZhRXrchEdDfpfb0R/G3mc4925ODL/iGn51
         vtbgXnQV0cwBTDyqEtd0o5MzAhxLgA8y03kq2XpaoAU+aotzErr2o8ljhyph/i6D1Dgl
         TlQc1lYmnQbEb9/3Nym9ZoFaKEiEcVdM+SvGFwGoRyK9ItHQz8jVPWyY0u1m0rzX/68/
         BmaUNSPgk+2SfVIlEZEkRQ+RKo14qJEN23oueHmn8KDKcURCFZmOegVXKn2aT22v2o1V
         5BTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:mime-version
         :content-transfer-encoding:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XkvYgmSpTTKDPEnaw7DYKoLRcBSw3mikuxqT7WjcEHM=;
        fh=U0NE3OLKRuR37tOU95GULDqeGPm7BKlg1QAORKd4hZ4=;
        b=OoSLQ/Mf+fTpYMBus3mP0RCFpYHHDxYiHvpnNfhMPMuIGtKVRc4ky78/z9egsXzuN4
         k/5e9+McZ9tN13LNkqbgFENE2BjCSZ/CXG9oQkVMC6KZYEbAeHVo/NIyWXc3V9Z8yT1P
         AREtqvJZGsTHXHy9+VliLG3Z5X4+riOXMG1/iHNi1nEkPgK+kF75D6vodDUrKeNIvhFJ
         TSaH+YwFI5xi1bFSMbEaDjx/yTGjS0tIBN8/HqDm2M/3h49e3dtP8a1kOczol2nTTCRA
         5cpIx5+YMe/064sN4BLoOoeqOJjVDkPC6vxA/EYR+WbasqcRumiJzBV21mSAQhgWCXHL
         ZccQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of baishuoran@hrbeu.edu.cn designates 202.118.176.6 as permitted sender) smtp.mailfrom=baishuoran@hrbeu.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752830379; x=1753435179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:mime-version:content-transfer-encoding
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XkvYgmSpTTKDPEnaw7DYKoLRcBSw3mikuxqT7WjcEHM=;
        b=hyPr8ivOg/YYhauX9c1ej8zHnXOeckkSnsmPVr7hD6hY98AkuoH/SAvvups5hlppVs
         pSHUjAkornmCIE4Jmct+taIQqcP93VnTZg68q36xXAFGu8y76PTPo0gXegYUXyasJ5ee
         +NXa3SvgALwD7l9dxkWP3BqlBocNwDq8rfCn9PQDvA44nhECroOKh5HIxjXdqSLlt9wF
         wdqfmNfNG9DLIQRDHoYQ5MLHIaL1fiwbkxhW1JMdA36AWbLaXydaS6HH5kFrQkwFFgh6
         ajleaHfB6tqZcqGVjbp3jnRiOr1IR56BQ+eLOWvL8R6/lqmSw9WaE+1NXLl9Pb/NtcQp
         4r5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752830379; x=1753435179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :mime-version:content-transfer-encoding:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XkvYgmSpTTKDPEnaw7DYKoLRcBSw3mikuxqT7WjcEHM=;
        b=K9kItQBIMKpbJxqWivuRdPpSxWvsrtnPt5GJ2yfouO+C4ghfrCJu2d0cm8AgyEVQnu
         rz8oE/myEpMS0TBy6tIb1PJfzXYQFfTtH7GXYA8WAqVAKbDRrxVqKiAHjqldlxaFjgE8
         YH8IpovbKPmlGtHO9ZM+MPdYJiI17EYM01/yr0wbGwtLle99lIBc5nqRzmvkn+ZQ5EEo
         +MhCKQP1nil1rXPxL5ZPD/Muv6y3kB3POTr4TS0h2OrynpEKWtrnLUzsCFLXSLPyyqhe
         8NU4+BGE9tSyswA0ltvMCvYfnA49TzDlLQLrZxhlPBPuSwsfBVxQtaTDXQrgEGg5DY38
         ViyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVN3vNruiOF5NhxRz3FWYWt8N6TClnkOngnuSju/fKDUP1QrF31EsqKtrXF+Iyx7uGj4xkeg==@lfdr.de
X-Gm-Message-State: AOJu0Yw67/jYYVS4X+YR/4WXBWYk+5IiK1A17cs10ELmUR8p4puVZZqh
	HV8eZPSJLGZfI/4cMIzdyvbLAJM9Mm/PDywImyB4kiWPh/hBIDLWVKGG
X-Google-Smtp-Source: AGHT+IG13eapTBzRpM5/l3vce1GNuIsCl6Pe21NswdgLlo+WBCBnGQ4wRu+3beqPut8xJAK7XefUmg==
X-Received: by 2002:a05:620a:444a:b0:7e0:c012:d1e9 with SMTP id af79cd13be357-7e3436327e3mr1531431785a.53.1752830378818;
        Fri, 18 Jul 2025 02:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcuBWlr8ZiMzqRlRvo3fETsN3mD53m9606F5XYTASuArA==
Received: by 2002:ad4:5d4e:0:b0:6ff:16c9:421a with SMTP id 6a1803df08f44-70504c4a058ls26298276d6.2.-pod-prod-07-us;
 Fri, 18 Jul 2025 02:19:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4hKdC8MVSK740MHXXEx7wSGUVQbGwTDSBFQgNsWEap4Dxf75p66f+rpyfBbSLMLitp2Jvzvgjh5Q=@googlegroups.com
X-Received: by 2002:a05:6122:91a:b0:52a:79fd:34bd with SMTP id 71dfb90a1353d-5373fbd58dcmr5664275e0c.4.1752830377720;
        Fri, 18 Jul 2025 02:19:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752830377; cv=none;
        d=google.com; s=arc-20240605;
        b=jSxRyS8sT4+DKLQ9jsfrrbAPAeC6ZVdKbfrgndC8PIEreZA8bpAqZGYiPsCCdFYOBn
         9wW2BAfspwhlVYhcH9C2ZF2JmBAAn3m3wYwwALV852WMEwzeMbIjPIunJMyHLBp1GCrI
         3GR1c1CjfdJPXzGHgZ8us/m0529ODjt/obCcHanTUWeCRDn8bUuHxNq+MDhBVES05HZo
         gGW8GefVNL0LA8RRCzZFGSRnT7EVkYPalObhHPgayoxSuT6WTxenerSld/gsyfIvWOzo
         q4trIYdvGv7UUQlkabPxrE254RRqGno/GuHPvwkc5j3MxOQF6Qm2E19hfK+dSFDBw5tj
         +x7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=message-id:mime-version:content-transfer-encoding:subject:cc:to
         :from:date;
        bh=p0VnAooMBWKZT+V94fEb5TuoijrqDqR+0iBzez0F2ow=;
        fh=Noa7jAQLYI/Vduv80ozmko4GV9vW+tgzk+GGB1M7szU=;
        b=YWqlakN2yXR0EE5niCtiKVs+YTQemL7ndYRIjcgBhTVIItYFZwrH+zOt1G9gBoCjn0
         Z9BGI+XVmPlgtzj9khJDfnx7RA0IU1wnCJKtOuUOWcpR1eNHZoJ/rYsuPYhpHRlDWAF8
         CLevo3fnPVOB7B0SeXifxvtnhmBkK8dvCxRzKBT3rDW40tR9f0W5Ml5Bsx+keMX34nSh
         TZJ+WTj/xdbe0ViTdnuKIeSGnZmBsHXH/wZI90ETQ1LHGFPXGmczUuBcLhvGbAFCUPza
         rm/H8XUpPE9rnj8jKqlJl+GM9293/vWzCHkKL8K0Iyx5I8moatBE18Pl3PY3lPd13uCb
         E2pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of baishuoran@hrbeu.edu.cn designates 202.118.176.6 as permitted sender) smtp.mailfrom=baishuoran@hrbeu.edu.cn
Received: from hrbeu.edu.cn (mx1.hrbeu.edu.cn. [202.118.176.6])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-53764d7b1fesi71142e0c.0.2025.07.18.02.19.35
        for <kasan-dev@googlegroups.com>;
        Fri, 18 Jul 2025 02:19:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of baishuoran@hrbeu.edu.cn designates 202.118.176.6 as permitted sender) client-ip=202.118.176.6;
Received: from baishuoran$hrbeu.edu.cn ( [172.83.159.137] ) by
 ajax-webmail-Front (Coremail) ; Fri, 18 Jul 2025 17:19:30 +0800 (GMT+08:00)
X-Originating-IP: [172.83.159.137]
Date: Fri, 18 Jul 2025 17:19:30 +0800 (GMT+08:00)
X-CM-HeaderCharset: UTF-8
From: =?UTF-8?B?55m954OB5YaJ?= <baishuoran@hrbeu.edu.cn>
To: "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
	"Andrew Morton" <akpm@linux-foundation.org>
Cc: "Kun Hu" <huk23@m.fudan.edu.cn>, "Jiaji Qin" <jjtan24@m.fudan.edu.cn>,
	"Alexander Potapenko" <glider@google.com>,
	"Andrey Konovalov" <andreyknvl@gmail.com>,
	"Dmitry Vyukov" <dvyukov@google.com>,
	"Vincenzo Frascino" <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: KASAN: out-of-bounds in __asan_memcpy
X-Priority: 3
X-Mailer: Coremail Webmail Server Version 2024.2-cmXT5 build
 20241202(ebbd5d74) Copyright (c) 2002-2025 www.mailtech.cn hrbeu.edu.cn
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Message-ID: <746aed.1562c.1981cd4e43c.Coremail.baishuoran@hrbeu.edu.cn>
X-Coremail-Locale: zh_CN
X-CM-TRANSID: CbB2ygD38WiiEXpoYgNUAA--.11244W
X-CM-SenderInfo: pedl2xpxrut0w6kuuvvxohv3gofq/1tbiAQIHCmh4yegX+QACsT
X-Coremail-Antispam: 1Ur529EdanIXcx71UUUUU7IcSsGvfJ3iIAIbVAYjsxI4VWxJw
	CS07vEb4IE77IF4wCS07vE1I0E4x80FVAKz4kxMIAIbVAFxVCaYxvI4VCIwcAKzIAtYxBI
	daVFxhVjvjDU=
X-Original-Sender: baishuoran@hrbeu.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of baishuoran@hrbeu.edu.cn designates 202.118.176.6 as
 permitted sender) smtp.mailfrom=baishuoran@hrbeu.edu.cn
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

Dear Maintainers,




When using our customized Syzkaller to fuzz the latest Linux kernel, the fo=
llowing crash was triggered.








HEAD commit: 6537cfb395f352782918d8ee7b7f10ba2cc3cbf2
git tree: upstream
Output: https://github.com/pghk13/Kernel-Bug/blob/main/0702_6.14/KASAN%3A%2=
0out-of-bounds%20in%20__asan_memcpy/11_report.txt
Kernel config: https://github.com/pghk13/Kernel-Bug/blob/main/0219_6.13rc7_=
todo/config.txt
C reproducer:https://github.com/pghk13/Kernel-Bug/blob/main/0702_6.14/KASAN=
%3A%20out-of-bounds%20in%20__asan_memcpy/11_repro.c
Syzlang reproducer: https://github.com/pghk13/Kernel-Bug/blob/main/0702_6.1=
4/KASAN%3A%20out-of-bounds%20in%20__asan_memcpy/11_repro.txt




The error occurs around line 105 of the function, possibly during the secon=
d kasan_check_range call, which checks the target address dest: it may be d=
ue to dest + len exceeding the allocated memory boundary, dest pointing to =
freed memory (use-after-free), or the len parameter being too large, causin=
g the target address range to exceed the valid area.
We have reproduced this issue several times on 6.14 again.








If you fix this issue, please add the following tag to the commit:
Reported-by: Kun Hu <huk23@m.fudan.edu.cn>, Jiaji Qin <jjtan24@m.fudan.edu.=
cn>, Shuoran Bai <baishuoran@hrbeu.edu.cn>



=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[ 347.632078][T15036] Kernel panic - not syncing: KASAN: panic_on_warn set =
...
[ 347.634330][T15036] CPU: 1 UID: 0 PID: 15036 Comm: syz.1.17 Not tainted 6=
.14.0 #1
[ 347.634672][T15036] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)=
, BIOS 1.13.0-1ubuntu1.1 04/01/2014
[ 347.634672][T15036] Call Trace:
[ 347.634672][T15036] <TASK>
[ 347.634672][T15036] dump_stack_lvl+0x3d/0x1b0
[ 347.634672][T15036] panic+0x70b/0x7c0
[ 347.634672][T15036] ? __pfx_panic+0x10/0x10
[ 347.634672][T15036] ? irqentry_exit+0x3b/0x90
[ 347.634672][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.634672][T15036] ? preempt_schedule_thunk+0x1a/0x30
[ 347.634672][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.634672][T15036] ? preempt_schedule_common+0x49/0xc0
[ 347.634672][T15036] ? check_panic_on_warn+0x1f/0xc0
[ 347.634672][T15036] ? diWrite+0xec1/0x1970
[ 347.634672][T15036] check_panic_on_warn+0xb1/0xc0
[ 347.634672][T15036] end_report+0x117/0x180
[ 347.634672][T15036] kasan_report+0xa1/0xc0
[ 347.634672][T15036] ? diWrite+0xec1/0x1970
[ 347.634672][T15036] kasan_check_range+0xed/0x1a0
[ 347.634672][T15036] __asan_memcpy+0x3d/0x60
[ 347.634672][T15036] diWrite+0xec1/0x1970
[ 347.634672][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.634672][T15036] txCommit+0x6bb/0x46f0
[ 347.634672][T15036] ? __sanitizer_cov_trace_pc+0x20/0x50
[ 347.634672][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? __pfx_add_index+0x10/0x10
[ 347.673063][T15036] ? __pfx_txCommit+0x10/0x10
[ 347.673063][T15036] ? lmWriteRecord+0x1102/0x11f0
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? write_comp_data+0x29/0x80
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? __mark_inode_dirty+0x2a4/0xe70
[ 347.673063][T15036] ? __sanitizer_cov_trace_pc+0x20/0x50
[ 347.673063][T15036] jfs_readdir+0x2959/0x42d0
[ 347.673063][T15036] ? __pfx_jfs_readdir+0x10/0x10
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? __pfx_jfs_readdir+0x10/0x10
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? down_write+0x14e/0x200
[ 347.673063][T15036] ? __pfx_down_write+0x10/0x10
[ 347.673063][T15036] ? write_comp_data+0x29/0x80
[ 347.673063][T15036] ? __pfx_down_read_killable+0x10/0x10
[ 347.673063][T15036] ? __pfx_jfs_readdir+0x10/0x10
[ 347.673063][T15036] wrap_directory_iterator+0xa1/0xe0
[ 347.673063][T15036] iterate_dir+0x2a7/0xaf0
[ 347.673063][T15036] ? __sanitizer_cov_trace_pc+0x20/0x50
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] __x64_sys_getdents64+0x154/0x2e0
[ 347.673063][T15036] ? __x64_sys_futex+0x1d3/0x4d0
[ 347.673063][T15036] ? __pfx___x64_sys_getdents64+0x10/0x10
[ 347.673063][T15036] ? srso_alias_return_thunk+0x5/0xfbef5
[ 347.673063][T15036] ? __sanitizer_cov_trace_pc+0x20/0x50
[ 347.673063][T15036] ? __pfx_filldir64+0x10/0x10
[ 347.673063][T15036] ? do_syscall_64+0x95/0x250
[ 347.673063][T15036] do_syscall_64+0xcf/0x250
[ 347.673063][T15036] entry_SYSCALL_64_after_hwframe+0x77/0x7f
[ 347.673063][T15036] RIP: 0033:0x7f4d361acadd
[ 347.673063][T15036] Code: 02 b8 ff ff ff ff c3 66 0f 1f 44 00 00 f3 0f 1e=
 fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f=
 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
[ 347.673063][T15036] RSP: 002b:00007f4d36f01ba8 EFLAGS: 00000246 ORIG_RAX:=
 00000000000000d9
[ 347.673063][T15036] RAX: ffffffffffffffda RBX: 00007f4d363a5fa0 RCX: 0000=
7f4d361acadd
[ 347.673063][T15036] RDX: 000000000000005d RSI: 00000000200002c0 RDI: 0000=
000000000005
[ 347.673063][T15036] RBP: 00007f4d3622ab8f R08: 0000000000000000 R09: 0000=
000000000000
[ 347.673063][T15036] R10: 0000000000000000 R11: 0000000000000246 R12: 0000=
000000000000
[ 347.673063][T15036] R13: 00007f4d363a5fac R14: 00007f4d363a6038 R15: 0000=
7f4d36f01d40




------------------------------
thanks,
Kun Hu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
46aed.1562c.1981cd4e43c.Coremail.baishuoran%40hrbeu.edu.cn.
