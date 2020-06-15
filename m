Return-Path: <kasan-dev+bncBC24VNFHTMIBBQNUTT3QKGQEKJXX4FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E06C81F8E7E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:50:43 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id z12sf10807149iow.15
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jun 2020 23:50:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592203842; cv=pass;
        d=google.com; s=arc-20160816;
        b=0xOiM1lUhns2msF6KYtxvszapKyxrVCOBCLtpRsVvVMPJA/gtTHPlZI9ZERHmF56g9
         PiOLr8Nfng5G5kESOMqVnl7rnVS/l+uwHpJKZBg0CnK0ljKcwZBntdnd7ntlO5V6eNd5
         kCcEWh289VMXYLEH1IzVcFaHDSIERA2rMNyO9gREGz2I2pQ/KTrd0dEL5ntmBQJbWHLh
         kd7YPutFC1xWAyTE+xP2QOFgJgn6sBDEWkPa42dabwFV2/oT9AXMP0aNIdeB0gQR8crY
         m55R/AJ5YBPC1RP4hcZlazI6y+47HBmc7rhNnADwm7HO77LpCi/+0jgC6G0z+k+KwHyi
         Xf1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=2fL1WJjpnzZS4gYUZu+WS9K3iNgg4NNwbn67tB6XPQk=;
        b=AS95/sD6f0Sbm1dOtN9JKVlIb86a5Pz4hbu0XlbFdAbtF/Jn3do0y/lf242KtoMl6W
         SxMqtFA0CEd7u6/tYCOVLl2Q7+a3R3ZzRY0Qy3JjKTs5pWwoyGTawRFxXBxaE0YlZJ8L
         sD9tKyNV7Btwo0eAec+KL4JSi/RtCdagxqB8qZsFwJezeok0/64uBOhjNwAWJI2IFCDH
         ZlCguHegNOda03aA6ogU9nyjuRQw1u+ZVsc4MPc/vnLjs+QIHBgmZA0MBsp40sOXAijU
         cweEoNy09fXVtEairEoXUzRRcC0o/QTyHmHs/G9GtiCJOIM7pj1LyrgL/iNVNB1ylFJw
         ppWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2fL1WJjpnzZS4gYUZu+WS9K3iNgg4NNwbn67tB6XPQk=;
        b=pq0ua4ZQXXsjCnznQ8YUfjp7Z9l4M/v7u7cdq1ljRH2yZsBQF+jE5T5wjuW3+RTIaS
         nYDUIF13sOB3DwEZBtU8nkEOLuZsonBWQ3SOLYJmbDxZxhFJCqYzKTxkzUVsZFKwRT6Q
         IDKWF+9/rOjpz+yv24eBGGGCeW0U/E/iYQXek5gdOHifXQ8N4WnTyLmjb+GoioV/Za38
         LoVDcWM9NqhLsRBC0eKNhb1yemMSwnaJbV+xPRoqICWRL6wD9DC9DX1hmanUUx9Y1SC9
         ITe7AC16ymb1P46/DyQLlN0j64ar2DYOhcb3y7Kt/aAu1lXmfajLFcTtISVFZJpqpGmA
         pujQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2fL1WJjpnzZS4gYUZu+WS9K3iNgg4NNwbn67tB6XPQk=;
        b=gtohtOjbLIrsqQEWzYuKAjcIFdAsS7BeVI5wkqi7Icaeak8BUzfYjtrZ27FrQzNfvC
         ZoThz7lcn18+PtBIQ5DOlfXyxl2wWVGFas6x/OvMNYvon8aXSDe/MOLLtGbU/kpvpiD8
         xFQ+ZP1U8HtzCNr5WuPLLBy+++ATNgLXZaCGH9gSbhSWu9hsO5SrjilC+xnP6y9TUxT5
         5ZgUqUpwodY11GiJ9JJ5plYq/bDuIR+ZJ5G33o3kuYZJGGeFS/RtzL+HrqIYuajqpbWr
         2eg0GW3K/fk8I+1BpX+TYQAVi2YTJANxNuTFfTE5EdtzimXBDBcT5xkFT2RlTL0dWCyT
         cUaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332/x18QewygI+1IYQ+wUSrbiRWAMeyBuHyjRtIDFD+WfG271Kw
	SI4ZJRyhCxHubbIBuKzwJs8=
X-Google-Smtp-Source: ABdhPJy86Ft4NF7rxPauEtZkaZXpVK859rw20skkzo3bn27S4ozMZ8F4qEB4MRVkpaKqchixS1GN1Q==
X-Received: by 2002:a5d:96c2:: with SMTP id r2mr4004579iol.192.1592203841709;
        Sun, 14 Jun 2020 23:50:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2106:: with SMTP id x6ls2430551iox.8.gmail; Sun, 14
 Jun 2020 23:50:41 -0700 (PDT)
X-Received: by 2002:a5e:aa14:: with SMTP id s20mr26765439ioe.58.1592203841346;
        Sun, 14 Jun 2020 23:50:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592203841; cv=none;
        d=google.com; s=arc-20160816;
        b=ycsYKuh3ybkyk+1tWJiT6rSUmWUdClw4fFncZA6gFax5kXfGo58QGoScAKZNgkdjWW
         BvFXYo8HUarFtYaCAc2Xusi7DYxL/pZykaijs10u6ndMBwUMjmFma9WYKIOp77gqZsxv
         jQru2hEm94AtIG5Hbn5GxirwLgmvyQTZ3A+cwJ/RFaC8w4teLjI5YnnGfcOr6wp/T4xN
         /8nxT541enos+Hr6Il4beqO5rRX7gyaYDH/TmA+444OU6fqpyEznbzKX75+uSZ+jkmCf
         MSUUZPfybDoNJykmVQ1z+3HnprQJJDfCy/XXhY98V6rKcaFQnOepuCBqCjaNSen4n2tM
         RznA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=QAH0PXD5fb6KPl76OXDnfgzHQy7z7VJ9quSl5605HUI=;
        b=ulvL1AgaVBzlGeU0bl4Adflw/XY+jyETDe5J6LzLpHNi2nAA0OVPKcm6plJhOAVxpE
         VMYbqSNigw5mH3z4Uiv/v8yCmNwIq19Xp9dQvzrj1PThaGVEFubEOnaEgaS1ayp6/Nni
         V5p1tidJyJlb3TJQoJ1hvOO8IJEDkYZsgP62ElzOu+QnhxEHf/YxpAXRwgHWJ3JverS4
         TcDntaYpP2fx6OK7ySFqXk4C3lQbboJwNN/xw2ROrf29osh9l77kV0rmJ88X14akqnGN
         wBoMYEag6FBQsZe7LdpRa7fqEUTSZxPgZniwAnev1z5bjfgTTYk6Z1s1nx0iG4uJegWf
         yGKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b1si781266ilq.4.2020.06.14.23.50.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Jun 2020 23:50:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Mon, 15 Jun 2020 06:50:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203497-199747-SnEJ7UhSKp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

Walter Wu (walter-zh.wu@mediatek.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |walter-zh.wu@mediatek.com

--- Comment #1 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Andrey,

I try to make -hwasan-instrument-stack=1 and KASAN_OUTLINE=y, then it gets many
false positive case as you saying. We break down the case which executed
kasan_stack_oob(), the following is shown.


a). Modify the following testcase is not oob case to see why it is triggered. 

static noinline void kasan_stack_oob(void)
{
    char stack_array[80];
    char *p = &stack_array[17]; // it should not trigger

    *(volatile char *)p;
    pr_info("out-of-bounds on stack 0x%lx\n",p);
}


b). trigger by kasan_stack_oob+0x48

[   36.096929]
==================================================================
[   36.097867] BUG: KASAN: invalid-access in kasan_stack_oob+0x48/0x94
[   36.098465] Read of size 1 at addr 00ff0000704875b1 by task cat/179
[   36.098996] Pointer tag: [00], memory tag: [04]
[   36.099421]
[   36.099996] CPU: 3 PID: 179 Comm: cat Tainted: G    B            
5.6.0-next-20200408-dirty #13
[   36.100617] Hardware name: linux,dummy-virt (DT)
[   36.101049] Call trace:
[   36.101489]  dump_backtrace+0x0/0x260
[   36.101976]  show_stack+0x14/0x1c
[   36.102451]  dump_stack+0xe0/0x150
[   36.102944]  print_address_description+0x8c/0x398
[   36.103485]  __kasan_report+0x14c/0x22c
[   36.103991]  kasan_report+0x3c/0x58
[   36.104470]  check_memory_region+0x98/0xa0
[   36.104981]  __hwasan_load1_noabort+0x18/0x20
[   36.105501]  kasan_stack_oob+0x48/0x94
...
[   36.118039] Memory state around the buggy address:
[   36.118593]  ffff000070487300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00
[   36.119247]  ffff000070487400: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00
[   36.119894] >ffff000070487500: 00 00 00 00 00 00 00 00 00 00 04 04 04 04 04
00
[   36.120473]                                                     ^
[   36.121067]  ffff000070487600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00
[   36.121712]  ffff000070487700: 00 00 00 00 00 00 00 00 00 00 34 34 34 f4 74
74
[   36.122271]
==================================================================


c). We think the wrong is "and x20, x10, x9", x20 doesn't get correct tag which
will store in shadow memory, x20[56:63] and x1[0:7] should have the same? so
the next tag comparing may wrong.

ffff9000104a331c <kasan_stack_oob>:
ffff9000104a331c:       d10203ff        sub     sp, sp, #0x80
ffff9000104a3320:       a9067bfd        stp     x29, x30, [sp, #96]
ffff9000104a3324:       a9074ff4        stp     x20, x19, [sp, #112]
ffff9000104a3328:       910183fd        add     x29, sp, #0x60
ffff9000104a332c:       d000eec8        adrp    x8, ffff90001227d000
<page_wait_table+0x14c0>
ffff9000104a3330:       f944a508        ldr     x8, [x8, #2376]
ffff9000104a3334:       ca5d53a1        eor     x1, x29, x29, lsr #20
ffff9000104a3338:       92ffe009        mov     x9, #0xffffffffffffff          
// #72057594037927935
ffff9000104a333c:       910003ea        mov     x10, sp
ffff9000104a3340:       b3481c29        bfi     x9, x1, #56, #8
ffff9000104a3344:       910003e0        mov     x0, sp
ffff9000104a3348:       52800a02        mov     w2, #0x50                      
// #80
ffff9000104a334c:       f81f83a8        stur    x8, [x29, #-8]
ffff9000104a3350:       8a090154        and     x20, x10, x9
ffff9000104a3354:       97fb24c7        bl      ffff90001036c670
<__hwasan_tag_memory>
ffff9000104a3358:       91004693        add     x19, x20, #0x11
ffff9000104a335c:       aa1303e0        mov     x0, x19
ffff9000104a3360:       97fb2466        bl      ffff90001036c4f8
<__hwasan_load1_noabort>

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-SnEJ7UhSKp%40https.bugzilla.kernel.org/.
