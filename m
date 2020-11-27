Return-Path: <kasan-dev+bncBC24VNFHTMIBBC4XQT7AKGQEZPAOUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 734BA2C67BC
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Nov 2020 15:22:06 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id e68sf4111162pfe.4
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Nov 2020 06:22:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606486924; cv=pass;
        d=google.com; s=arc-20160816;
        b=NzLDf7N1D0ey9CmeVnws7ywgPetDJWKtp4I0dBjdvC5mGhSEeKmPOmN7wYa7xFM537
         qeqdeT1VhaPS3wZCnmNW6E7ndZI9om6HqxePaCM32YEoMKYjSvN5eTzaC0jqkktEawZm
         db9mjasKH98auRx07/6ZXq8JNhv0Ii8YGAgQU354ulqCyhXFHcmz374yNRxGv07v4ep9
         ZAV7yECgGKgKNmsVwauGIBk/dCjPga+gnXZw8RQrJj/oqbevdI9k87UMWqkp/KHXZ5Fw
         JGv5Mqt1W/rsJSPpjO7QHQthVo+JIdSwD91BZ3CBQzvBo61tE+zTBDhrM0GUbvJijlYI
         a9sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=pW1ONhMzacjKwfmikpjyOnimfb08We5V6P8VYE7iytI=;
        b=xAraBNYkWoH/NJbbwmjBe+OjcGWDpaC5KiLmTh7rQQLyTCAlJkNiP/JSf2wn+RunVW
         ifLWhg55b58hao0EAlxelnZBxJYHPBI6hM1rHEkSEmB5d9FbsoK7AgbXm9swBsE1Fp6e
         ufoiuGcRdk/7lrAa5Bv0RjYIisFoC+Y5n0OFyA5gwMi/rS8d6cT+fDq/hq+AsL28iv8z
         1k9SHANaEpthFmk2zVoSW50+TlWXQRID7QL1PJ+ESMqEKCi+qNwc5ooN3c8pTEULgKgl
         dRK8MVJsz+8wAlyhmIWu0nc2xJ4IyEkintN0nOa3Ui37a1add8IgOe3bF4xW1Quzn80W
         eVTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pW1ONhMzacjKwfmikpjyOnimfb08We5V6P8VYE7iytI=;
        b=DA5kYRiLpm1dWF0YgWxoL6BYDcQBZvOf6V55rsQdOhp9zXMSAHcirWgPpDgFVYrN+U
         xEZfKqCJu2W1XkV7LE4nZAeNbrnO/KpJOPWRiiDCk5zkJokOK9MwSnypRAz61njKNAgQ
         bknDobkiyO5g5yQ4EZuXotVtFcekB6HR+0ns/l4CjI/qWt3O0hh2H83ybadcyTzcF9c5
         q5Wy25kPhLL40hPpDxGKK5ZFx0xC6ZkZvftv1rxNcTVUEzyWKv1Z7dsy79bskJ/ALNnX
         ijgeIH5Zs+dDwKH6XO0QZ+b5c29Te4YdLEqmwKGLXl33JeYAtrbvSvzlXZXgyKaNtUWe
         agNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pW1ONhMzacjKwfmikpjyOnimfb08We5V6P8VYE7iytI=;
        b=HarbAL6JJZliqmGEu+Na8yds6HAGO8hLrwzDv5MxazrzQdMR0Hgnb5X0fomUG6P1Nd
         yL9m0/4ciFzuA5UkfqRdQ6TYVtP8vmrTL48CiOXVtElUW5Wi2MJe351xv3CfMTZQ0P8h
         MTTACTBnYDzpnMCMqm77YFGfbR4jnpptzucYcKojw5+qBcuLE4ueVjPI2RZRxsp67/rL
         +kFqQEj9MOxRA8e90QQa7UIq5ZeLHaSVH5AAk5PoHk6dopCdD6rK8Ots9+Ci2FDhfnh9
         ffUdEwlZ8Q3dbHHLBjb99lO4nOexLKSJ/SyfPZgR35ijvIWCc3GTK3GQzikUDlqXUFOU
         yeBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fH22CA4f8kidFtw5JLqYjm03R7b4Y6l2X3WuenaVJy+C47yd0
	SiD9mVvmYkHmVIBxS0CFRkY=
X-Google-Smtp-Source: ABdhPJzFmq1xbI/mntNoDt3xMk4nF6RxqoMEpWIdTRkkgF9H6LbpCuiLa1N0MiC6VAKEZy+AOpS4Og==
X-Received: by 2002:a17:902:bd01:b029:da:5bec:9ca2 with SMTP id p1-20020a170902bd01b02900da5bec9ca2mr23239pls.62.1606486923867;
        Fri, 27 Nov 2020 06:22:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b42:: with SMTP id w63ls2082438pfc.10.gmail; Fri, 27
 Nov 2020 06:22:03 -0800 (PST)
X-Received: by 2002:a05:6a00:13a4:b029:18b:cfc9:1ea1 with SMTP id t36-20020a056a0013a4b029018bcfc91ea1mr7308247pfg.25.1606486923360;
        Fri, 27 Nov 2020 06:22:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606486923; cv=none;
        d=google.com; s=arc-20160816;
        b=s6VCtxBrC7ZmkQ0JDMR7abrjw3wx33m2aqMJztCxGW32p8zEgMXtYUv4Nz8GwiApEI
         Pc09M8U7v8+V9WOY4Y3s3YQltiQuMS8TghS1UpISJFVvH6TFv/qlFJAAdN6lAVvA2qEW
         wN86DDn8gOTC0Rs0cQScby4hxSIyYAD154SRnwzLNymXelJMDRxjSXNCpmiLf++fNdUA
         mW1/wmNA16t0wRi/+MljHNpIMPgkblVOMALyfCEgPRHhtjWzl0380DColLQnYW1pE+fP
         WgnB6Gs3d3+itF2ienzn0NonG9kuzDpNU+mt0j3PK/p9CGIq9pH4rgl7SGWuUVs8nWUt
         WNBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=INtXgL3krp06XCmPk+2Hf5pOHm455u7mUihrohGAqmY=;
        b=rBp5y8hKw1pZH+yB8HvSkyhXHyV7sslluJFQ/HUUXl3yeasunvd7Z5YI4yRmvWt5LL
         48NcthXLovHlDj1trnhjDo/+3FI1Cq6el+UR+0YdULqdJKaM5pPJHvri+552PrvQe4hI
         r6Tg8sgJXzUUTzuhD4AKPDWdc0wFAn2lQVCFGUtVMblsbCKD/df2mV+tUAO1h8kwWbjg
         99MwjXBtUmDZ/M/EG56twYf4YyJTnOpWcB9rduOPBX+R/wHzO2fbxb+fguEq5kmQ3VMe
         YOVnL5CTIZlxDTloh8Ilx2/Gf4qgYdKer0C5YMBzZiLkdX8NYl5Sn29Xs9s7mpDOao34
         OdKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l23si470923pjt.1.2020.11.27.06.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Nov 2020 06:22:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Fri, 27 Nov 2020 14:22:02 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-210293-199747-kFv4rosaBT@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #15 from vtolkm@googlemail.com ---
Created attachment 293845
  --> https://bugzilla.kernel.org/attachment.cgi?id=293845&action=edit
leak reports for softirq with line numbers

by today  5.10.0-rc5-next-20201127 is deployed on the node.

It seems that leaks for hostapd have miraculously disappeared but now reports
for softirq appeared. Enclosed the line numbers pertinent to softirq.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-kFv4rosaBT%40https.bugzilla.kernel.org/.
