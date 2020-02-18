Return-Path: <kasan-dev+bncBC24VNFHTMIBBU5AWDZAKGQE7MPQRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id D27FA162A69
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2020 17:27:00 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id x10sf14254467iob.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2020 08:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582043219; cv=pass;
        d=google.com; s=arc-20160816;
        b=P6OREX2pMykeu4LICky9cmmgEOmWUXFDcKPhS1QxTkUqmN1NlXvTZwe9mrQyLdEaOq
         kfircmpKZ1EkC1AjsSE9DrvdnGtWEZKM4A/lPMwFJIYFjqabHyE3xozfxXHvv0bCrRnI
         0iMh0YOAHk/or9+iwbDBa/Yai2K/CUxizdErZZP5RGiuyFHzELbSo1nddffhGY96jCXO
         qofO9KcLb4hT5aaxoG51NYCd3EX9CHX9yZb+rRR+Uo34RKuPUa9FtkpjP0/bvFpHX4Ma
         RNvfKPcswQJ4fBxX8JVpCj3UwYahXRMV55Cl2EzN0to/9IZPB+Nn9iGpnWBbTlLaWt2Y
         xJqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=rlTsOm25zn+S9wwEwpqiUAw1VPtkBNRukBW4DH4oByE=;
        b=CNTyUCdRnUw3xgp/aGp68Ez5MA2BCVHmZe4wpm1WxrwO5x0BVfYCdsm62ztcSPfXaf
         SpZw9vHs3SDzWy3eByXla40kGaGGkAvMvj/ATx+AjvtEeHlsSrvvehb44KADVuitPxZC
         mzAvR6ybY+EDatzzFQ0HGskdeK6Uj6eH8zqsiY678S98wTS9bUyXQ0t5NDK2tcQfOD/7
         2PDFFSkuD1+LbFHB0wxnRlGw2bpaV3AenOjKJSPil0pJ7u7CgJ3YaDVDMWawr6OObEQE
         ty7zPocc03bMsBEGc4Exk+wjTxfWQuqj9LYcc7fbDdGf/g6C7+GzElA8YNPj1Oh4nzv9
         /law==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=z2qo=4g=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z2qo=4G=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rlTsOm25zn+S9wwEwpqiUAw1VPtkBNRukBW4DH4oByE=;
        b=BPL7ala4MzbzHVC8/idYud9lTV7dycEwaR01Zon2H67jkQ31kWKCX1BFsN6aoOBUL+
         F1+53pOHFJ2HpSiBJL9lkZT6yKcoHJDPHcYTJTRclK9WDF/+PIHoN8ito+bSe5uwzRXe
         XVJtUoBs4+zXoD/s3A0r9uM0vZZ2sewoBRMHJf8+rnuaG/CSa65wB9jfWb1FtQP4YYTx
         Gjf/xXpKPOuTIhoesoglKOXvdk6AY0Kk4In9SOn8Xf02vsmDW6snVPt4qaJpI5d+f7nZ
         SvOGRdZoJztGh2X0Ammj9PscOs7gOiXj8vPc2U0MJpcYi8bBpkd845cATUX536gFZlg0
         0HAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rlTsOm25zn+S9wwEwpqiUAw1VPtkBNRukBW4DH4oByE=;
        b=nKDNkIJ5eiVAcYt5/giZDShNCyKU1Ud6saPATaD639gLJrsIjwArMJv9K61XdmbUEx
         ceFStgsld37bs0zO+7U1JnHrcZTNil3L43TsFurjycIgUIQDIpAJCN1hT8DpP2Mi7t0z
         rylaEhQoxCmiczzbasMvBHskKNxdNDP11uJQdslo/lp0Fs41frEeGVwXi7eC4dQsrfMq
         QMZrbruYbuSkJNDdmGkBBx4svSuY/FTPdKom5KMLms4KJ9HBbiGg1JB9sNGMb1mUWj8I
         an4QUkU7cChvRrMu4VHqjmS2Wwbe6u32kWrzXe1Oi7mLxwKs278Z/swJAyFLAGEDhdfw
         TqmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVOZhB/PcEbatIR1BYIK0FPlw5ILzoXVjjoEZVPFCo09+1JsvJ6
	O2rM5bslRlxOrHeMwliFHJs=
X-Google-Smtp-Source: APXvYqzF1eVVKIDJj+F4MZKEtTPx17+T9b0bta8QhgY4dh6akWfHfCQNXbhH7u8wbtYnT/dg5OxDzw==
X-Received: by 2002:a5e:9515:: with SMTP id r21mr16370948ioj.169.1582043219527;
        Tue, 18 Feb 2020 08:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2907:: with SMTP id l7ls3322654ilg.8.gmail; Tue, 18 Feb
 2020 08:26:59 -0800 (PST)
X-Received: by 2002:a92:ca8b:: with SMTP id t11mr21188165ilo.227.1582043219176;
        Tue, 18 Feb 2020 08:26:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582043219; cv=none;
        d=google.com; s=arc-20160816;
        b=yeYBWu4GJxXgL9cHof3kTaDdBbYdGLYTOR07ltxZb0NBa7WpawaGneokijc5onEDwD
         MPxCg9yz1YGmW7sLEOMNbvC/865Pdv4QsJsFZWBIv4ohebQkD+wmuWqb1txK1SnhORqd
         1DwK/lBObmHV18JgQ4JWaASXV516HfjaVbbLbulaHMymLqH88afcQrjuGEYaKsmiCrqu
         CFa0S2tImtL91b9HyJIhhyg3C+Ay5b3z8K39fQHxrZRrf+st41wXlfW3/OU60Opxoc+5
         u2O/ZnQomjujq8g5E5mSIbcx9GRCFoofbbhNVZ0IVYfp40X50KT5795FHPz36MGjyD2k
         zm9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=7+ngEDMXfVU/fbXiGnQCUv85TLVKnkLojJ0F+Mmk8YQ=;
        b=vF6vKP4pJyxps3BKDt6yBoFLeY1/Ir4ssOs10MEBuxj6u7VPbgmXhfHmtr3Oq5EohK
         l6Zx8RkJvum7KBfFZXjPx4A8O9pwIClloqzrUSE6LpzhfjVz6Dt2extscrCdc8y2gMxL
         Alni+r7i6zQQahKew8t6YAzFQSpyn0HRUQ69OGOTUcS7CVZ6CFUwAXBtY67C32tQtOlO
         B139+yxiiLjLHNEok5AzbIEm981GRNo/080Sr46ArJ/451oZsUA7WKxIeq9BMNooLB5G
         IS2c0r7XE4BwYXTdkeHJK4Uqg4nqYrhCtcOs0F+ChfPcPmWcSA35Y/kD9zMSwDHy0wF+
         SERQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=z2qo=4g=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z2qo=4G=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h4si222089ilf.3.2020.02.18.08.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Feb 2020 08:26:59 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=z2qo=4g=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 202009] KASAN: make compatible with VMAP_STACK
Date: Tue, 18 Feb 2020 16:26:58 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-202009-199747-a3v0tPUW48@https.bugzilla.kernel.org/>
In-Reply-To: <bug-202009-199747@https.bugzilla.kernel.org/>
References: <bug-202009-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=z2qo=4g=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z2qo=4G=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=202009

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
This is fixed by the following commit (and some subsequent fixes):

commit 0609ae011deb41c9629b7f5fd626dfa1ac9d16b0
Author: Daniel Axtens
Date:   Sat Nov 30 17:55:00 2019 -0800

    x86/kasan: support KASAN_VMALLOC

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-202009-199747-a3v0tPUW48%40https.bugzilla.kernel.org/.
