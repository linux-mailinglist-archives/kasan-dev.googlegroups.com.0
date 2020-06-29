Return-Path: <kasan-dev+bncBC24VNFHTMIBB6FU433QKGQE4O7LD3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2713C20CCFC
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 09:38:33 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id q6sf3163867qke.21
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 00:38:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593416312; cv=pass;
        d=google.com; s=arc-20160816;
        b=AqvN9KD8oXD8sVKQFVHt0WIhKb7w7uXcWYI0qRT2HYCVuGct+c+SCgx9yvLjVdQRfK
         OTY7AU6/34zTZ6yJ9wYvty0DqjnCPs6Kbjn8V1VwqiaukWZbcU0dCyj1hza7FYRJaS4w
         VFqQKIbzZbYY6UxE3JDrgvJkiLIeu3l0z8zDhqxQPevSGQ4/Hcb2E0dglAK85B+pLeGq
         Jh8ozIeTjiEK7HEj3EqeSibI4Gx0hUDqkjav7BvWx7Ol9QPdN6MH0BQ0T3MBdXqIzwAk
         7rTgA9Yn8GWhUUmAqTm1avhdIdEx8G8z2xbupigILR7J7FI28CywbziQF/t1of4lXDhU
         18zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6oFgZWkf0/2/lwlUlvxbYe8eemQIqPzUsm12q9xudY4=;
        b=y8cP3XJcqG0eKF4ZfLA534DR0FYZ28yXthfVqQtTGdg5qQ1v+GpSkcQUwJE36XfEMV
         0dMMVzaPC2+w2ivMULfPmK4pelrnDFLxG5GbdyRkdUk1zHnIikpQyZxmbtASVl7N2k+t
         8FWuC9WeOWUFKPuuf/dA4dTTFnALmdffTMTYFKtHsMNvCXcm/gUjTG/32yeB75YbU846
         oG51EBF8Um9ULcB/EHR6+VpOWcFrLrtV7a+EDAvPBWyOhhe5DyTMEJesdoH+HjKrhU4M
         cSQPVvwmqjdwB/rIm55PBSKZ4X86m8496geJmDLMsuQglrTGaAkahI+JBnVM3rEFbB12
         /4KQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zg+q=ak=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zG+Q=AK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6oFgZWkf0/2/lwlUlvxbYe8eemQIqPzUsm12q9xudY4=;
        b=NvQtKQuvTOqY2olkQlZSwHfwPj3/82+GwiQzGkfMu0jLIda0CXSOasLCNl9PZN/yc1
         oRacGSWIBjLyYx8FU0cAn00XUdGDki59Hb/hNHZWXWhD2MY09UAbiJ/VmLG1sRnAJV0p
         iF4YU5hkPDW9RxQikFBvQ7pXFIV7mS6zvjXNPTx0xqbg5sb14dsCEZhFtX/330NvCDt7
         LNlAshNy0XVn2LvF4NGRnHA49AHWzamvTzAyyVXY4kWqLRy7adjz/bYFFjOCyTPUAW+X
         mfALfHTcZCHA5VaM5NieA5p7GKOgFOXxXGU05kwBOCif0fm60XGcN+Q6/mHxs0of1oNr
         nyBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6oFgZWkf0/2/lwlUlvxbYe8eemQIqPzUsm12q9xudY4=;
        b=IZBJSXEsIdDI1R3ILiddYaipNh4TWKTG0zj3Pvc4VvtZ+qaXUOzZVMuHzc2s5LnL+f
         RXeayUiboeQJMLTcDQJrccKzU45hA5RUKBayKJmUFWL5l+g9CbsK+8JL6q9mXWIHLUmK
         BO7uHUvHivzP0KhAD/cdI21817S/stbzr0q+YFNNKxbc0zYldderAe982bkSCvbQTpAp
         mKs0Q4d5gaSqVGYjCJMw3iXlhMWGQs98laYDt15ic7E2QzAfrV6+U19uBZNwuPi1j2uf
         tzxVgbLjzcYDWpusI9dsK7710UcLVtwnGwzaAb/C1x/eQQrB8WvXGLaql/9VoJTV4vKe
         PJyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326FCFpGjmTbMGHflXbsl0P3zl/XeEfkHBH2cFWzJ9yF6WMc7f9
	NNGe8urJJ5LKfXbX5GaVTWM=
X-Google-Smtp-Source: ABdhPJxgehZhrEHKCYWfXKih8WEbw9jajug7DjkRTsjx0Suw1czexZmC0Y92RjTTH/M5F9MKPCBKzg==
X-Received: by 2002:a0c:f788:: with SMTP id s8mr13519111qvn.169.1593416312167;
        Mon, 29 Jun 2020 00:38:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3287:: with SMTP id z7ls6423087qtd.0.gmail; Mon, 29 Jun
 2020 00:38:31 -0700 (PDT)
X-Received: by 2002:ac8:4d5d:: with SMTP id x29mr14673667qtv.358.1593416311864;
        Mon, 29 Jun 2020 00:38:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593416311; cv=none;
        d=google.com; s=arc-20160816;
        b=avdHk3yBSqLmq92Lzm9OBA1zyiuXZhcRjppmQkGGPE49pdZseCr7DOdbNQp03pVJQj
         aj19kj7XiTKQ3osncJnnC6854SvPT82qvnBszpZPWgyS5rQ+7AnT/lPfgLTdk540EF8/
         75KJMPyehreLXr2oDhwZ8yi4Lfe8cIW9MSA3y1MHfNkrsPWdgpKLRw/q3QGQ6bjo/kKL
         8X/+1uXW8J5zh5T1pUYXYflBvbIYjGww0ZYlpfQBU+62b4/5MfHzhJ6bOw+K+yAv2PYs
         rNbDIhJKUhSZ6LCoOqJnW+f9UJ7NP+o98EeCw5vRMtXdNglcrSmKz9btsm/F5q8rF7iu
         T+Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=sDgTqa0tlcyA6m+0dv0keBEZPTLk9VeHrXiKNGTpTgg=;
        b=LcenHdBp+A6D4bNVelpIiY2wxRhePY6d4LmudcfsXb9PkSO/0v7oPQPck89phHqvn5
         prFpjBHNE8BzCTBihf0jGOlpWXgRllvicPNA6d2t8CvtFuKSpmlmppiTK2w9ficzI0dj
         /9fAbJ6PKSDz1IdJjD3uu2i6Uzgn8d6mDSq4V2OAIme7MHJTCoCypZyNsLtJKH/chP/5
         8y2OdgJmdavW80y1WOm00K7RpqzYYMI25bTMogPoLnbZ981bijvRuwebWB1UTKj9PIk2
         kXxiH60mCJXqUHb86FcLeCqLI8GxDjuTL6cEDMwTEKvG2rx6XxGnftrl+pftF0ILrj9i
         PHaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zg+q=ak=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zG+Q=AK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c67si1846631qkb.7.2020.06.29.00.38.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jun 2020 00:38:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zg+q=ak=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Mon, 29 Jun 2020 07:38:30 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-JUsgLfihHN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zg+q=ak=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zG+Q=AK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #18 from Walter Wu (walter-zh.wu@mediatek.com) ---
I found inline instrumentation root cause. I am not sure if there are 
still other issues besides this.

First, I write one testcase which always reproduces false positive case and it
is simpler, please refer below information.

struct foo {
    unsigned int    t1:8;
    unsigned int    t2:8;
    unsigned int    t3:8;
    unsigned int    t4:8;
    unsigned int    t5:8;
};

static noinline_for_stack
void fun(struct foo *spec)
{
    spec->t1 = 1; // always trigger kasan report, but it is false positives
}

static noinline
void kasan_stack_oob(void)
{
    struct foo spec = {0};
    fun(&spec);
}

[   10.508952] BUG: KASAN: invalid-access in fun+0x30/0x40
[   10.509222] Write of size 8 at addr 4bff000070b2f520 by task cat/179
[   10.509487] Pointer tag: [4b], memory tag: [08]
[   10.509676]
[   10.509859] CPU: 3 PID: 179 Comm: cat Tainted: G    B            
5.6.0-next-20200408-dirty #25
[   10.510175] Hardware name: linux,dummy-virt (DT)
[   10.510362] Call trace:
[   10.510632]  dump_backtrace+0x0/0x578
[   10.510880]  show_stack+0x14/0x1c
[   10.511147]  dump_stack+0x188/0x260
[   10.511353]  print_address_description+0x8c/0x398
[   10.511588]  __kasan_report+0x14c/0x1dc
[   10.511796]  kasan_report+0x3c/0x58
[   10.511997]  check_memory_region+0x98/0xa0
[   10.512214]  __hwasan_storeN_noabort+0x14/0x1c
[   10.512439]  fun+0x30/0x40
[   10.512621]  kasan_stack_oob+0x70/0xcc


Second, see the below assembly code, I found the shadow memory which map the
address, it store #8 value, please see that "mov w12, #0x8 // #8". It should
store the tag of address? So we see many false positive KASAN reports always
show "memory tag: [08]" after finish KASAN initialization. This is kernel or
clang bug?

ffff900010d69c7c <kasan_stack_oob>:
ffff900010d69c7c:       d10103ff        sub     sp, sp, #0x40
ffff900010d69c80:       a9027bfd        stp     x29, x30, [sp, #32]
ffff900010d69c84:       a9034ff4        stp     x20, x19, [sp, #48]
ffff900010d69c88:       910083fd        add     x29, sp, #0x20
ffff900010d69c8c:       90023728        adrp    x8, ffff90001544d000
<page_wait_table+0x14c0>
ffff900010d69c90:       f944a508        ldr     x8, [x8, #2376]
ffff900010d69c94:       ca5d53a9        eor     x9, x29, x29, lsr #20
ffff900010d69c98:       92ffe00a        mov     x10, #0xffffffffffffff         
// #72057594037927935
ffff900010d69c9c:       910003eb        mov     x11, sp
ffff900010d69ca0:       b3481d2a        bfi     x10, x9, #56, #8
ffff900010d69ca4:       d2d20013        mov     x19, #0x900000000000           
// #158329674399744
ffff900010d69ca8:       8a0a0160        and     x0, x11, x10
ffff900010d69cac:       f2fdfff3        movk    x19, #0xefff, lsl #48
ffff900010d69cb0:       5280010c        mov     w12, #0x8                      
// #8   ; w12 should be the value of shadow memory
ffff900010d69cb4:       d344fd74        lsr     x20, x11, #4
ffff900010d69cb8:       f81f83a8        stur    x8, [x29, #-8]
ffff900010d69cbc:       b2481c08        orr     x8, x0, #0xff00000000000000
ffff900010d69cc0:       38336a8c        strb    w12, [x20, x19]   ; w12 write
into shadow memory
ffff900010d69cc4:       39003fe9        strb    w9, [sp, #15]
ffff900010d69cc8:       d344fd09        lsr     x9, x8, #4
ffff900010d69ccc:       3873692a        ldrb    w10, [x9, x19]
ffff900010d69cd0:       d378fc09        lsr     x9, x0, #56
ffff900010d69cd4:       6b0a013f        cmp     w9, w10
ffff900010d69cd8:       54000060        b.eq    ffff900010d69ce4
<kasan_stack_oob+0x68>  // b.none
ffff900010d69cdc:       7103fd3f        cmp     w9, #0xff
ffff900010d69ce0:       540001a1        b.ne    ffff900010d69d14
<kasan_stack_oob+0x98>  // b.any
ffff900010d69ce4:       f900001f        str     xzr, [x0]
ffff900010d69ce8:       94000018        bl      ffff900010d69d48 <fun>
...
ffff900010d69d48 <fun>:
ffff900010d69d48:       a9be7bfd        stp     x29, x30, [sp, #-32]!
ffff900010d69d4c:       a9014ff4        stp     x20, x19, [sp, #16]
ffff900010d69d50:       910003fd        mov     x29, sp
ffff900010d69d54:       52800101        mov     w1, #0x8                       
// #8
ffff900010d69d58:       aa0003f3        mov     x19, x0
ffff900010d69d5c:       97f0647f        bl      ffff900010982f58
<__hwasan_loadN_noabort>
ffff900010d69d60:       f9400268        ldr     x8, [x19]
ffff900010d69d64:       52800101        mov     w1, #0x8                       
// #8
ffff900010d69d68:       aa1303e0        mov     x0, x19
ffff900010d69d6c:       9278dd08        and     x8, x8, #0xffffffffffffff00
ffff900010d69d70:       b2400114        orr     x20, x8, #0x1
ffff900010d69d74:       97f06480        bl      ffff900010982f74
<__hwasan_storeN_noabort>
ffff900010d69d78:       f9000274        str     x20, [x19]
ffff900010d69d7c:       a9414ff4        ldp     x20, x19, [sp, #16]
ffff900010d69d80:       a8c27bfd        ldp     x29, x30, [sp], #32
ffff900010d69d84:       d65f03c0        ret

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-JUsgLfihHN%40https.bugzilla.kernel.org/.
