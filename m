Return-Path: <kasan-dev+bncBC24VNFHTMIBBBG3QD6AKGQEJRORXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE662885F4
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 11:29:41 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id h12sf5318010qvk.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 02:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602235780; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQcDAgs842oa/1OHUQjeMPg7P/LSPSxjsuyI7u6Gg9+WBwhcQkIyrh7ihuPUAgvgwA
         iLanCu1eionquf/0JBkGVcSqXz3oKSb+hNQ3RkJcjhVa6fbkjM6IkvY+hB+NtP3e5JyN
         RXVttGYtlBvxVkJCmd4HYLeOxG2eSPdr6MtIEbNAZoN8ytugllSLakMji5Sb7yNz6tkO
         uBOrkxQNRZY4+bXX8/7D2DqqLiIzokJCWOzAyr8UDksbRDgRKRUawTMaNvAibiRQ5O6p
         lkib1liSR4HIN+DHfRZtKZLdHa3pPJ1YG/0O+yR8bxAysddZg59YDSFganI/bR9lc1H1
         AqLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=iWa0ZVAYKy3GeLhw4OmDcHwl5qHqxz60Fq7oUMuZZ6I=;
        b=x6HNnZgyMmcrvXAhGYY1xUcazWvjpJlFghi6KEdJmaIwUrGbf8Y7BMAtmfFsw1bMZn
         HnacJwiyKY25glySKPjp3zPUHD33K6ZqgWVjvlCQcfUwoJrfaHW5ae9ky9X/Cc1HEZk7
         3kgY289GtOy6lNNcT7BCpXCKNzyiLJFHIfF+dHWj0TO/2lSf1jO0WEPuEOANCDSlwhnd
         C/H3wjq8fmJES/10/CTSwQOJz97JhZosBGbRMpuu/S4DOPedmrO1MiCp0aRhmTZ+B01b
         Stz6OxEGPIOM9Lk2ho2gSjr7RavL7mN1B2lLIGCOOA2I66hY6GZEmF53lhPuSnMMe0E+
         +b6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iWa0ZVAYKy3GeLhw4OmDcHwl5qHqxz60Fq7oUMuZZ6I=;
        b=ivD0ufYSj32mdeXWD4GNOZz7+w0QBtqjxPL8ufUdsxywVNY/fKALrNpfzWDvrX/rDl
         alHTlP2Q4mbw2JTAoNcjHVELqbsV6QISZebsiqXQGcJVUwNpJzZt+eZOMjXfmEudKyCU
         L0Gro+HAN1oO2omc7aE53Ot4qlUgLmttBMQMi9cZS2MOip7UOeoqcBYR1WBjgdIQYbk6
         jlIeVSR6RO/8inGqoLYWirND/DiBX0AYqKTK2JIvyoSJrWLq/0JF8C2/0SDXJjTVaalC
         cl1EmqKmqvo+dEeMTevOGudz7+vEvUUejq0oNnyU+Pk+Yxg2U4hfsotqj0q31Ya1HGe4
         yqHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iWa0ZVAYKy3GeLhw4OmDcHwl5qHqxz60Fq7oUMuZZ6I=;
        b=bOU/Vek3p+yTN6O7sEdpqLE/9amG56FLnLMkawX/7eWH1Im1VJ4ExPKhFYAT846AEb
         XAnTFflaHORzmxBCSAVg+OgSdaJC8/mxZvxi7RnJ/l27o0bDb0G9W6byK8dkL9Uw3/Ws
         l7dPHwLxlraX0ty+yxwMtl1rY+Lyp4q9Hlxljddf3fuBGfVqFkumuvimeoRjN65DIDGq
         UGlpvncKYmC5NoFVhIqZ5F8F3wgNqgzN6ypKFeT+w0HG/ZTWMkpnkBnzObBd+l4Q9YFl
         mviLYW/t44XD1BGMhq14qIzdzE/c9iF27M9fmCw1wG3nb2fxZkqKe3kwgI/mTExsTnc+
         4QFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yK3GmddXxAO6IGvgVFybF7cYoGmZSyskm+0QlH3wvaCcU2yef
	rrSeKhwNvV+DBwwvj05NNWk=
X-Google-Smtp-Source: ABdhPJwLSYEF+I5ojnEIuhyeb0b1gJ7mZe3tQQtVriEWOSVQWR8tLhry9zMiydnoCUVXKdW2+0XPZw==
X-Received: by 2002:a05:6214:192d:: with SMTP id es13mr4073746qvb.27.1602235780610;
        Fri, 09 Oct 2020 02:29:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9c83:: with SMTP id i3ls2051822qvf.9.gmail; Fri, 09 Oct
 2020 02:29:40 -0700 (PDT)
X-Received: by 2002:ad4:41c4:: with SMTP id a4mr11788651qvq.60.1602235780235;
        Fri, 09 Oct 2020 02:29:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602235780; cv=none;
        d=google.com; s=arc-20160816;
        b=CyPwdH3Wm1ffYD/HtW0NNxjRcsEuD1JJiALTrfdh5PD/bfoYQu3cvSij11xOSzJCea
         QZi7JwWYon7kLO3a4/qObTbckl0ZVunvqugwtylkuQJauCT+pyIaFgBoWVFMNadLm4NE
         xN4s0t4vLFesddTx/UAw1PnG+Ud0O+lWnCDUIyD3pm4KNXha5JilTA0gUoAsoA64LIFf
         6nWHekXZDGR6HcrZqUNjyiJJ6YU9HAiLr45cWfHiFX3oKGJyxTLnVuVQTo9CHvvzLJIe
         DbiGpWnULaKaW8GqnaRzRrSwkL6s5PnwMr+FAEhBe/AibaVDY4USC7yRDx+S9b96R7Wl
         PQaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=s83b1BBTV1LEoTCKR0ijaeOfyxnl6mlDRYlETiyIpbI=;
        b=TN/nsmh2Tpcid9cBwidefMFnamXXA1ssTds2JDChZukhrDapUQbiKb5sRTEYMBdO+U
         b9o8AeAs30qBcBtGTz4S0ny/iWGCz6QwroxjV9IuNY/2ej5Dhpzo5cnf3coXh4WlfnFB
         CrYRBaI2h33jk5nXs4FRtGG+jlpL8T4BRf3byW2ZO4iwmlgNJlJrQD2Wq3njhye73DJk
         GbHlUJGNschhjcG80o8aWu5pkplPfAp8vx1pfn3Qd0VHDVNL/QER8NsmMpaj+I72NuPm
         lobMYIscUr8XBv6o/rS4HVEudo08lBuILjRgmvZCwQQUi5AaDMuCUfU2YuqI7LX34wbX
         oQJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k17si591059qtf.5.2020.10.09.02.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Oct 2020 02:29:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206269] KASAN: missed checks in ioread/write8/16/32_rep
Date: Fri, 09 Oct 2020 09:29:38 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: a.nogikh@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206269-199747-mTYnOwX3In@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206269-199747@https.bugzilla.kernel.org/>
References: <bug-206269-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206269

--- Comment #3 from Aleksandr Nogikh (a.nogikh@gmail.com) ---
So we need to detect cases when we read from (or write to) some kernel address
instead of an address that is mapped to IO, right?

In this case, I think it also makes sense to instrument
ioread8/16/.../iowrite8/..., as essentially they can do the same thing.

Probaly we should check the target IO addresses agains memory ranges allocated
by the ioremap/memremap functions, not just the usual KASAN checks.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206269-199747-mTYnOwX3In%40https.bugzilla.kernel.org/.
