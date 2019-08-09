Return-Path: <kasan-dev+bncBC24VNFHTMIBBX4ZW3VAKGQEPGKD3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 922CA87DC0
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 17:10:24 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id j22sf61580342pfe.11
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 08:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565363423; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQJVZyr8YoMFQn0qB40Q2MCZEN4Q1LoA0hefL1iSpoCIHqoaiQkP7m00KJY3eMvgOC
         J5KBazxs74Z3kVWU0SUNiyhbzQ3h+7Hfjl3F8vZRgN/jyu0RwXj9A+C5MbjgLfcgm1ez
         t1caWsN1ui3cRjGjWbbY3E57GzBInxrnsRBvLJxe0zHwO8RE2rIiAQaDm665Ke62QUsB
         hvS2AnCoQBSrReVwykiEBxfTIfqLfrRVRq0gEz4vXcx/3+hbSmITZ3Bv0oA3+b1hTuqS
         yCMQxRC4csiQSIHrnrEmdJ3pnApxlnaPgjUZ7ImJyihEkSAyuK4/nqguREUBLuyoDQQf
         If9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+ZKjTM84mFGw0xJiVFKSLcsMsxdFznZVIIYpoSZ9hF4=;
        b=xzimoy20AFPCt7f0VOcQoMIBLl+IXqJiQ2394EtI5jEVuHTdoRiE+uMJrmE9AtdyW+
         QJEUhsX5wI6i4sCS07UkQnKZ0TPFJ1DzTiI4SHuedtJif/zxiJPr3b270vtfCvMqIUUv
         bxTtEjifFKAiBgA4IwsfTbTastSPb25SDdyLN2klL+KHEUN8NxmQJyN2K7xPi33ic8jC
         yT+3BCASfu8KNBl57Z4NwUXGDU0qocZ5iKdoQCJ4M4fY5W/PVY2TwkL+9PEeYefL3jOc
         yKKGwZMpd5FRWQEwmGnNmYH66o6LaHVbrCfWDBbV6kzyXlhoyeFs8Qyxn7u+L2BojWlq
         OEHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+ZKjTM84mFGw0xJiVFKSLcsMsxdFznZVIIYpoSZ9hF4=;
        b=hWE7qKQrAqduq+gyhs8oFwZMtD9HTDTE+KPOTOvlcUCYbvt10GRvqpJC6vryuuOShs
         iT7lA3Phl/dwZ8md2qtcIdU/JHjv9WlogVZxeaGK/CzHjm5C1ZhOhXfQVkJu4i2EkOdr
         6ymxYRomzKu3m22KKAnZoht64QJX801Kk/la8ex8BVHlxKC/ppfcUK9tVNl7Li4HKqNW
         a/V1ddeEvvyod36+iqf/WQp0rCL3pTMPwzFlVSWojKr0OEIl4/YZRCN5QzCjf4hG4oQL
         qCdSHju7m3REkbZsBDDKFptHkNEWnJHSjLv1az1AUpE22GYD6JWF7FQ2bwUVjfZNrNhv
         gpvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+ZKjTM84mFGw0xJiVFKSLcsMsxdFznZVIIYpoSZ9hF4=;
        b=BC4uRRLeLnynShEeHFXVc7KdYk8ue8s9FeIG7vNsSmGo3fSeG36ViY6V2rUjFhP6sF
         RLzzvqqPFhlfyJNAIjiG9iahCvbOxZ2SQUC8NfZtjrJ+VvOf912kC+qNlP/z1llvx5iT
         MY+26YgKHtxvXZuI7gzjl8JMYWb293plsSy4mEQ7DbktFCogE0ZIBb0SU8/Enb6ExkwT
         DWzqR5iNQoAx980bITCBEWUgrv0biucnBmAhFYNNCeCK7fISW7VW+SEm7boVjSbC4M1+
         r+zKKn5jDpNKTbdeJkQKkdNWwFET8tF1p/0wDaEBrjeMpjF7tPdJLflpiWHKYGLqC/MS
         hbxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUF1G/XLrsYh5EaOOAv/V1m2V/oB6uN0FP4yBqRPAUCdR78eFav
	BABv3Lx0G4dMJiFuKbXp7HU=
X-Google-Smtp-Source: APXvYqwx+EPsGslINxnuqqOQnc8OeBGuS29S13ulhbvlGIFbWaNDbwmOrfzyC7gfMSk037eiBxdbPw==
X-Received: by 2002:a17:902:a5c7:: with SMTP id t7mr19736408plq.288.1565363423350;
        Fri, 09 Aug 2019 08:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2704:: with SMTP id o4ls1720708pje.4.gmail; Fri, 09
 Aug 2019 08:10:23 -0700 (PDT)
X-Received: by 2002:a17:90a:26ef:: with SMTP id m102mr9804312pje.50.1565363423027;
        Fri, 09 Aug 2019 08:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565363423; cv=none;
        d=google.com; s=arc-20160816;
        b=UuG7Q4ZAWFeXm1GvdEq6yl/J7mumnAnWUfQVt2BTqHMVBRskRA/OTTMpbihaWSOI7/
         ospoxSZHAYWLRjCzmieSgC1kB32/YtdNM38jXoQwbZb+IlHBVDD8SgqOttg18eVEzbX/
         DdLHbqzwDa8uv1b1Q8hqaGAcQDIxB9KYLptTewvURw/ecud84Gd2jusUlB15P80t9e/I
         rXK/ENcEPPAaDyQXTiF822pqe1PA5hc1sTyi5htEAoU2LoCYclY9oVVRpoRkUo2Nl7kM
         ql+IbvVLELL8lICwi50sdeg3n9k/qrKmVJBftVezEgTjCBQMixYHnAIGFjnXG9pl2+Dp
         KhHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=d8jHrQtueTmFkq4fKBXRdXYPpHJrL9BQScPz6Yqpr+c=;
        b=NXm1RWf/dlXYvxxOtPu+vu5tPgEC9CteutxTc7hRKQjCalY5j5N1F+22h+SOWRvOKb
         OPBrAq4hpjVdc09t7lGvI+k+LB3Cxv3ZL3Z4Br+DtbyN5OjHCdAIUcYjhXT+68HHXJzL
         Co6yvB/2O6t8RBUt13o7BKtRZizrn8KrqV0qVBxP5Z9N+30DYXtmXEUt66yn1NldgY+6
         QWeKvShBkWEPijWj73YaIdbqK4DhhVrOsRQNNvZhFvQlu+S+yJzR9lySzyhs31OWlx0D
         W+6vkP6w3h61fjXx3I3pvq+wDip7eDK08OIIc1Wl8EXaA4/zxi0cHbtUfZEXaMutVUIZ
         nzMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id b12si165251pjn.2.2019.08.09.08.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 08:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id B57A620000
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 15:10:22 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id AA04620223; Fri,  9 Aug 2019 15:10:22 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 15:10:21 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: christophe.leroy@c-s.fr
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-qrQHHRDypv@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #12 from Christophe Leroy (christophe.leroy@c-s.fr) ---
Patch at https://patchwork.ozlabs.org/patch/1144756/

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-qrQHHRDypv%40https.bugzilla.kernel.org/.
