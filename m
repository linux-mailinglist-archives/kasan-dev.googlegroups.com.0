Return-Path: <kasan-dev+bncBC24VNFHTMIBBVFF7T5QKGQEJXB2GYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id D981E287535
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 15:23:33 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id k124sf3872550qkc.13
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 06:23:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602163412; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0B1s2QQ1xMRDKsBBwkx9H0O5ZmQgG2aCBxx4Mg2b/f+eAN2B+lle2eIJxXJNxctwx
         WESD+g37pJed8PepXSyAXhBK3jiiBQ49xpkcd4IkA7DAvNreSKcJVhXZ8KUKBiG2U3OX
         iZmYyMYhNzDGKROEjc1Ws4xbXJ6o1XQIKDhKXCItBDW3avDAGX5Jxnx88IjgJK2wbZsE
         Eig64SlQfkrMlY18XjLaX3hsRzhHQV+foPwlu58FtghlsjOHFLWuxvZFv+qj5R6j44Km
         blGgQAL5WcUrOQdrBZzLKgPG0IbJ+U2aI+ZTH/ieR5zZYDh0QcPviS2aQEB9jSQJdN5P
         z53w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=BKLTAJR7wyGVyz3XoWcyT+Nv7UEN8qfxe64O/gOCe58=;
        b=yy0YwlLCXK1It+gamynVqo+1OMqgaqFIdYJxGB36NLYjsUtv366Th2kZU2HL5Z+9J7
         E36CBDja84KfSjOsTAblHdZ22b7wCkO5EkibqiMKpNblMiIp6RMcnd2tSg0pDc110E+R
         PwYXX4ACkiqgeW6oww2KGa/YMnZAluODHCpotcEJ204CL7PBBqq8iIX2cKKuF1sVY6By
         HJcO2LagJzxm2ivpbP7zTQ7GzXCLcQdp8RX99ax6T5aL6xruraj0rT276EH4z5rhRMRw
         jlLmZlO/bYFc2beIM2/K8nO3ohYZ9pUOU5z0tPjnZ+L7PiUNi6Gc9hQ2v3FIiUyfQvdg
         hmlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BKLTAJR7wyGVyz3XoWcyT+Nv7UEN8qfxe64O/gOCe58=;
        b=JPyoOEge3w4Dvg1aNSfrjHvuLiOQk/Rsjt/lMjw6AC7knAJAWVLUt5qS+nZFUiYPqY
         0GQcyZSgRp9gLMJeW3Cufjg99Unc/yiRFH/0ZQ4qG0wCzQKRL7tLEOIrUasEmhYvkDhs
         /fVzgh6feXEd6Kz2MBWwMp+aGSz9pCDeUVuBy9ypW6Q9MlRXDRvYS3Z0vdx/T/hG4+4g
         DxN7W9Stt5vdaTdex/oHKw/XEtu0CKdzam3HajHodxbcmC7ciIsWvt50+gYiMFGYBmXg
         afq/dgfjAj58gdelpKNlzdWi//ruhfKYpl67TFThFhl4rco4mPA5rdVmkqmOJnamtcYu
         JWRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BKLTAJR7wyGVyz3XoWcyT+Nv7UEN8qfxe64O/gOCe58=;
        b=g3+vIjXfzEUzMyJKqdgrmKNIj3icQeW4GAS9feXkP2TS6ePkTK6PUI/cOhYPiJtKy8
         o03TNe6UC2G9K/Q6RwMXGFEPhWJ27LsuFSEqivX+R5UDjQN6fsGk6zH3TUuT5MrDzKqe
         VSu2tq8VT61hBjFfEFNvrrQQ2Xga4Kzp/1rTjqyHS3wOkVrEPy+1zQYbpfko7hEPsW99
         EJJPHFHq1zh6cyOd6HhPQdt3i5W5k6Bkdl1ICOsw5EFFG17A2GZWys1uJQZZMgFBnrkD
         zHjw0HpePTuxKt8bXZ67SkWIfCcRiUYLKZ2P2wi/5NB6nlVoE3WZysmSHUV9lYBwtHaW
         0Vog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533k/JjgXeSKcchKHhFAYtuKjCBAdWHaFNwd7C3imk9LqWyL5GaC
	C4/+N57jSJyJq5s+NKBus/c=
X-Google-Smtp-Source: ABdhPJwly7dZq85hQXM8sIixo8b9cqnoC71GPlSaR0DTYe6VIQ4M7VP2Efg63TZQvM+jtpYnF9X44g==
X-Received: by 2002:ac8:35a1:: with SMTP id k30mr8198816qtb.387.1602163412530;
        Thu, 08 Oct 2020 06:23:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7441:: with SMTP id h1ls2177742qtr.2.gmail; Thu, 08 Oct
 2020 06:23:32 -0700 (PDT)
X-Received: by 2002:ac8:1199:: with SMTP id d25mr8117037qtj.260.1602163412115;
        Thu, 08 Oct 2020 06:23:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602163412; cv=none;
        d=google.com; s=arc-20160816;
        b=KxLOgGwCoiaXld/R/SWAhB7Z6Qux1ccwLAevL+v4XFfAhgwjKaSsvqMTNyzwYAjarg
         MqEBWIrlZS6ZNKzqLl9LXT4osNclb93/jI1mui8dZqzrJMXdhgnnukYZQX0lHFwuR8c7
         /xu1tifvhcat6BY6UvF+VGLa3fzFzIbYd0ptj5sQd5IQt41gnwva0QuiY2SSg9u0nu8H
         1B35MJ0tiJ6mP+ZAOPFw0N8M3KkSilITraN38Xb6xYNVmrtbSA7f2sOgzGrFD1WSSiDZ
         NB7gK2td8nNVz+yMOm58Lsb1CxsRh45SXczZePzL2GIFT4MLRvX6oDdfcvi2C8M/w/2P
         I1mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=qANu0gGTWqJH3bNMz6fOPyK6iCbkVMRrHP5+zW3V6k4=;
        b=hxOs30aRgsrjS96HPBiVyFccrt3zhVGqvAhlypVtuYwJ1g8F/LRe1Z9Y8dBDfdH7MA
         nfvxQzq59rHPTDfI7ng9n3OEk7naQ5HGe/bY3UYlY0v6CjZ3yl19pc0KS04tWeN/N3kH
         ih0nBgx0+xKPkLyhlZYQm5W2pFlOxnZDNDySeqSJjp8Ri2kdxkbmSL0eXBZGhoP9G8s0
         id0y9ks+cccjR9BXQw7/awafzWtC0yNOnVecmtfVlbamn7kRrRyY6KMgSzr9WitvFSVy
         XbOWxSnYm9NUv9D/5GDi1q6RLS6CHk9T+mXC71DoTj6WNWX/ZQMgKjhjEgKf1+lX2IdB
         y1gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k17si358227qtf.5.2020.10.08.06.23.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Oct 2020 06:23:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206269] KASAN: missed checks in ioread/write8/16/32_rep
Date: Thu, 08 Oct 2020 13:23:30 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-206269-199747-tbkcriq2pl@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206269-199747@https.bugzilla.kernel.org/>
References: <bug-206269-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Aleksandr Nogikh (a.nogikh@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |a.nogikh@gmail.com

--- Comment #1 from Aleksandr Nogikh (a.nogikh@gmail.com) ---
Can you please clarify what check is required in this bug? These functions are
implemented in C and are instrumented by the compiler. At least this covers the
cases of ioread*_rep writing to bad kernel memory and iowrite*_rep reading from
bad kernel memory.

There can be (?) situations when ioread*_rep is trying to read from bad
MMIO/PMIO memory range or iowrite*_rep is trying to write to bad MMIO/PMIO
memory range. But that would require adding checks to
inb/outb/ioread*/iowrite*.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206269-199747-tbkcriq2pl%40https.bugzilla.kernel.org/.
