Return-Path: <kasan-dev+bncBC24VNFHTMIBB56PRL2QKGQEESS4SOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D13B1B7001
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 10:48:56 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id 5sf4637970uah.23
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 01:48:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587718135; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qp0YKGm/8si9m85szvIgVo84+K7VJFDyziGIyHtnFswPJhkejyXPRBq+JY+FXsstg1
         AbiztQbJUoOnABUmIyL9FI+ptcJfXLxGO1fsx32R9q2eQDPtJ4XfVxMePjQaHnU/wMwP
         wGxZ66ctKEZndqz6VpETq6XfuTGJMj67ZzSkkfOP0xC2JJTTegCQUC4TCa+iSL71VLYi
         yWVAo2brUfD3v53qRD7NnVxMAWfQweeUcozp5F9dfrKSbPgJulLOvNvF0hoeKcG6eXAq
         LBfUM3e4xriBliuoaHksFKjOSXihvYnPBTCIieUitSi3kg00yIPegIpPn/Cbg3U47qfY
         LTqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qZkScwMnsQTZc+o4y4ifn47XiLkEXL9LgIqRcPJtT04=;
        b=hf2bwxUXgANt+RU+t1x0RVHn9wBUIM0x7+ZfIj9MvEsZSN/1nQYRARmDIfCj0Rdv5X
         FRryYQCbE41AQvgmbvxgyUufRRSf+D1Lczk5XbB+hnreNzLQeQHLKe0NkE3MXktoNH2O
         uZq047FjnvMZXM+82c9Vi/Pm5/YaarEB7AFxBW1FtNlGytxa96XaW2JEDAulJy+jb7cG
         pPXVwGVzY47zmIhmWMB47ytGYVYyfV0lGhAhaCiPchqDK988NCOsnWs1lAkrBVTLSquN
         n4WwaiDtyRkl55wU73vhDoH5ftw4c1dSgtgf1wkmaqCURQBfoxBJCoVWHSKAWQ+hhHSL
         UwOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qZkScwMnsQTZc+o4y4ifn47XiLkEXL9LgIqRcPJtT04=;
        b=TpEiPL8YH4ifpA81iLjq0Sq062nvJe7Ng4tuCVXiV/VpT4ZX7yndgsBMnh+CRAc2i7
         IlUn4RILVJjfpHUJ6+cin9SVouXxp8JgxdpZilKkOiBvHDAMBj08q+TBIedVuFqTrWYp
         ys0RIev2EnJGtQUStbIU/17AxUDmA9nG5QhIyRvPUjCW/x79wM0X9EVVOzA11+aYD7hu
         WO71dhSxSfGkfCNncfz20/owBUm5oAw7bDgHL6ANT1jRjXp4oVR+A+fwYUHqEaVduzjI
         MiwtolLb+xvj0vteoJQwJFybX3aypWauKhKLzn+zz1Tuw0aZA3VmDT2BuA9uUhG5fDLG
         wHgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qZkScwMnsQTZc+o4y4ifn47XiLkEXL9LgIqRcPJtT04=;
        b=IP/h+RbGtb1/oB6j1hLCqc3qqqwYSmgnigRdeDw+aOtYqiPXfsMZPQGKlPQt4U1m4F
         YaYKwX2QPfzfNkETXPf1c7SJrhpEcJ8BQVvXRrPlFz+vYLe/RajOH8wPOFMqak+GSrvW
         mjttOtI5Kz0F7rZeFXUuWvAMfKkcmz0vKhAIuEvTEIsMxvY2ZkSqa9xO7RrbAdKmpRbc
         Qj/oS2Oiv+zDvWECbjPgeDpARfNsNjJjjYfVAl/vHpbkPEvbr5Jyotat+XXQK1NfHGcY
         uSp2XnOIpYBvDb93FP/TR3ohu5URBGEapEmPKJ5hRbMKRrAKjU99IOA3s5GjPvpJHCRi
         CsJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZ4p1O8GRZMtOyx0Ms1U2k4J4TnMfev0KbYQgOmkYz4u+SUNbIJ
	MqHbfmlvs69WJwwikcO3kVU=
X-Google-Smtp-Source: APiQypKMNzdqr8igw+AK61W54TIf/yYuqtIyNUF2p0gJkeWgaTtP1bYA5hMyVO+R4m7ai8hbj5VrkQ==
X-Received: by 2002:ab0:2ea9:: with SMTP id y9mr6522155uay.116.1587718135580;
        Fri, 24 Apr 2020 01:48:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3184:: with SMTP id x126ls1254325vsx.11.gmail; Fri, 24
 Apr 2020 01:48:55 -0700 (PDT)
X-Received: by 2002:a05:6102:392:: with SMTP id m18mr6926222vsq.38.1587718135243;
        Fri, 24 Apr 2020 01:48:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587718135; cv=none;
        d=google.com; s=arc-20160816;
        b=sOjAi707KTFOs3wYEDDPn1byDYCCY3531HzfhYiwVWVXfjfWN0JM32ZudRDf4B0dqU
         x43BwwmALILqiZ0PxSsGkzlWYxfWmKoaeZMUGYfg2OEIMnM+v9I8oZ5J5kpjvc3tUUm5
         YCfKnzxWy0GVi3nVEPss7gkwW7CCgDMQdOmYxGPQ80uAWJvySogXdi5GddGoQL46x8rC
         dt2kjnnLlniY+yIrYrZ6YGwxrEduhjYiolZu+cTkEF7tqRjvMKvz5GgwaPzg9Vl00Tyq
         ir6eebe6iySiNQXs6LiBlSmxP4GpYVUk5462HSodVBKhoCi8DrpGlRIDDxnUV3z/7lD6
         CBEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=tGyzZzqTmxgZNllqKkdsv7QNPm3/uuWlRI490sXRKcI=;
        b=zynQJIxAcS0aHodnjrnwQ1I3VSoVIziMidRJvwhmlYUqODPRRquXIk5rAcEb8WI+AT
         /dtToWKdaCawiZ+OREP9s5QaMnssqcsyLc1G0641cLwlYxiGss0wJPJTv9F6nYsEgJ41
         +zscVCF1C9Lz3Z5R48UQyjh1Mspu1fhY8TnO1UAfnraxg0UAvhkpQ1F0sBR5Qb7HHAOo
         AegMkKftwN4oj7dF0X5zjGvsXz2AHuogQFfds/s7LhriVY1AHw0nTpSdySGiUihq61Q9
         XXXCPW+CVuhKLFg9MhidrUljH6KIdud4aDcLJLDZPaRiy8T6DFTZ6hIRcAdtTDWK89QH
         BOOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l3si351165uap.0.2020.04.24.01.48.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 01:48:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 08:48:53 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-xH1YDlJBZ7@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #5 from Walter Wu (walter-zh.wu@mediatek.com) ---
I agree you meaning. but if we don't replace someone info, then the additional
call_rcu info must increase the header size? The tricky part is not easy to
implement it. ~^.^~

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-xH1YDlJBZ7%40https.bugzilla.kernel.org/.
