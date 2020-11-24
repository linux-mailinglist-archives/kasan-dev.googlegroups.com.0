Return-Path: <kasan-dev+bncBC24VNFHTMIBB37W6P6QKGQEL2HST7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 98A012C2597
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 13:24:16 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id t67sf10420190oie.14
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 04:24:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606220655; cv=pass;
        d=google.com; s=arc-20160816;
        b=bc5LiDloCC4mgy0+B4ycZl/U9ViNXEAUDxn+Ob30jKYpm6HVlhwrcds0Rz2ez2UP+j
         OgERP1VZOVDcUOlg2g7fiQ0dlEtbUhHVBHUslVS3msT9JqsI9npnYYiHo8MPoTonKV3D
         gAHG0PE4tqzo+82cj+bddD5WypB36KJO2Q/CFxTwEE9inAcNbEU/+uSlrZ0nTsNI3BCg
         YvGjBe4zfGfqFPzKZHFq2YVKwE9xNBgBIUofmkLgvQVDSD6x43CCsH5d2xr+wnOueu9L
         mK7FHa9gBiOGou8EH0Jnal8Hgoj1+tD/cRgKa0PCqvdjuNRvYL3aoadGaeB80TFxNNdZ
         B1jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=FLjbGQV/Kb3en04IOuzx94K/eY8+AlwugoW/xTKtTuY=;
        b=GYyy1lUv5cvDrWotO3wFUg+f41gVeD2xqokG7rdZDZ/G3BhSTO9vYhUYjl2MKuwmtz
         8TjeT+ZcryLhKEghsCggy4jAKMSfM7qMGoQyRtuoqIpVO8S4xZ1vZpe9gfpmHIiZAljH
         nO8OoUtq8HvBD5i+3cjmSCI35CTURvfJS/1XL3iJVgbzLNQl5UQ+DvD8SrXr9/TMofzy
         uDSXfs5DIYrVFDAnq6F2PRW+mb7WnBJTuNenUysROp7iDR6Cl/42kh+gCIB3dKEqXUk8
         xyY8ncSO94pD5xilxV1fwG7HWyX7y4BwOfAD7hh83YhOJ+QbYIxtgz8gfywfu+otyPqG
         afqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FLjbGQV/Kb3en04IOuzx94K/eY8+AlwugoW/xTKtTuY=;
        b=l5yDJXO7fgjASmYkVp3yKoNJ9JbHUam9IGqlOWFVnE3iWM3Te2N4nlYTk3xy0I4skp
         tMJiqa3+SK9nkUNFH5QpjeojrZSbIiqXtcvyUPneP5QsvyJ8JdgD5lqV0H33H1kzVGjC
         6YElpOgSVE0nP658gz5gM0RGfRBLZSJCm7bJs0lOvT8I2v5TeVbt3ncciETUgQagnYW1
         6obwUEgzpnm5TCZMsvhJ7d+glo8X4G7OrKLrugtWgWts+ETVEN5kQ7uFjhmTMmeje0EG
         BFAy8Paoo1t+8CF+LpROp9phx3+eSAEHn+uJ2LGWMIQTN8CEELGZRcE8TYlrUmtEelol
         WLQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FLjbGQV/Kb3en04IOuzx94K/eY8+AlwugoW/xTKtTuY=;
        b=jYmlG1aBq2OJkm+HgFJr1wazPz9UxUnxgCNwbIB19nz325Z9GGWziepgP8qYLEcBq7
         9uiGiM2WsmNM9OfTpgSsT2tvT6PZgwkv0FWmk3zXhFI6xvH91nycLzOe5TUl29hNAwvh
         CvlV1/Y5/4dZRGoLQO+IHXgcsWTqFiG/AUqdMPuk915P92oiqDLYDfpyL4YxlfhzwRvB
         Yast/Uv5jIaA1NsrmMFyf+u5R0FOprUqMxyusT0FD8Yp3qTnnBaBF09vgVKqGFfXM/t1
         B777ipyBWMhu69ZOhwhhWeAbcmA9XeJE4Ma6n9ZpaJ0rBMrv/pZ6d5Jx+BIXYWXKlaKv
         Ixmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/pTFLX13da2iad5CZWbyRajv/pBBs4CI1eo4mUSdKJkOSXq5x
	jPvO8XqWWdYXntxW/yBPgPs=
X-Google-Smtp-Source: ABdhPJw77OvavyWK0O5B+oYHFWd5e982B6MtscyVCH/MepI8FOJbn0CKlOSSy0ZUcqOZXGdhHK+nwg==
X-Received: by 2002:aca:c4cd:: with SMTP id u196mr2291342oif.133.1606220655172;
        Tue, 24 Nov 2020 04:24:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:130e:: with SMTP id p14ls4283646otq.10.gmail; Tue,
 24 Nov 2020 04:24:14 -0800 (PST)
X-Received: by 2002:a05:6830:1c8:: with SMTP id r8mr3101419ota.324.1606220654849;
        Tue, 24 Nov 2020 04:24:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606220654; cv=none;
        d=google.com; s=arc-20160816;
        b=nlDdInWJTKaNlOokSkuKuHXrnZXClGMu4VQXodfL73kVRLVq7mdCdprqr5pwgctR3M
         U7X2CxRtF+enJbrfkGqJDukU9hsOttgHVyMvFRw4hPthrD2CIt5Nm5TkxxoMTP8eJRUk
         LlSg0J+qDB/uLuknQqAEu8+5Nexf1zYhquUPE219lbFoYoJ6HRPNgK9+kSw9dOIM8bvt
         to0TdK3fu3hiuS0Stkgd5gdCGyNuO5lMacVOI/Iz6Z26dJA0szzmxJZS61U4QULhXLsY
         Yii9MFZbgChlJXT1LEodpJUyiujtuFwKxVtW2cRJoow10VfTJudzi3LsjJeclptuiilI
         tEOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=mOnLJryOTGgPEjK20vzmAQY9qkfsMqRd1tr4M11mJMg=;
        b=d9X44SNokAT5Zn/1Jy7NDTQNj32wrtlkQU5Xn78QktRTYt9tIrM7BFGlPhcsEoQmJ3
         7qdz+VTe25smF+T6qaUCEb24qZMaGng+hOSsilTGOSUp0apiJCM9BqziupcOm3ErsIel
         X0StzHkWPu75jLtrCrqpC1Q+If/cYeK6tbW7cUNqxMU+PEDQBjowuR9Y2KKZCW+YksXX
         zu0nEfNgmK6w6i1yUxdUR6rbDjYgbKMcvCDog2SmPFtXsx+23YZnXd9D5suGjm0zkCqt
         WTpJAQNfN9jWN+qFl3hgeZdeF+jdJ5zho3CZZL+39xz84R59r6sO+Oyh/SQ7lMWvpJq5
         jK1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b4si1099957ots.4.2020.11.24.04.24.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 04:24:14 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Tue, 24 Nov 2020 12:24:13 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210293-199747-I2cVGbExFI@https.bugzilla.kernel.org/>
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

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #5 from Marco Elver (elver@google.com) ---
I think this is known:
https://lkml.kernel.org/r/20201121160941.GA485907@shredder.lan

I believe they plan to revert that series.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-I2cVGbExFI%40https.bugzilla.kernel.org/.
