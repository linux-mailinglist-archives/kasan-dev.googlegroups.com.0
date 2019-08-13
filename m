Return-Path: <kasan-dev+bncBC24VNFHTMIBBR6HZLVAKGQENU3HALA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0205A8B78B
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 13:49:29 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id o21sf22589498otj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 04:49:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565696968; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTgtjBIcmoj/WO6dxxdW/fNTv/1kqyAfhLN/mRI/PUaKptZrG1AH3sPld44NKIzv2H
         vEIHG6eZxws1Yq5088ZsvoZjxqhCXF39dUkcvKm7TSMWunlND0keR8lyJjtosO2bs83P
         iD9Hx1whueO0WyFEQkqIrEAFZ6ma/pYErn4CUJXfu9rI268bMbmAHfx6TPn9dgbwonmN
         2SyE91OePl3zKScmWr1nDuIW0UjmIX+OSAfw39WmMYuPFcsVkmkV6grHQ1zy8cOrjDdo
         lCQC3fwpJLVegHL3DV24LDuZNgHS2eL8cAGINzya4gexbnONWI8rnuqgeA8dRlYaP8Tk
         dvPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=7Q7n0GqXUbm90zr89K7dyQsdhlso4FaG4qOm9CltdFY=;
        b=hwUwN9WyAgPvrKyY1Lr8C7/1VMraGBANzRejxeoySJi3cj9OMcf7QAjZhlB1mrs1gu
         1Ra8rhJ2ed/dACnVTMjv1sBGskXubNh3Xnr4Wo7j9iZji/MvAGpZOpXlMjCnjW9/RNbi
         6TvhEwsqUq1BeGNAjQTLJYZyP16Pbxex5PsDvEG6xszzmHcRqh9Uh0M5i+42ixYuaIyQ
         dajC6nAnkDUcwa/lhMix6xgEjNtVNJisJm6enZg2qzX519ASrXfX3XERro18286aCKcq
         aMAirgupbNzA/yrdxmnXStlH9EU12wrGaQdJiT2/xWWjz8kZfBqME7xqt0QMAnx0nSwi
         +uHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7Q7n0GqXUbm90zr89K7dyQsdhlso4FaG4qOm9CltdFY=;
        b=CtxNrKH7te2HhJdViH6Z5S3azrtbdAi2iun7L2hVXXhs6fYD/GUFhwNSvLorpORX87
         u1O3QljDVXo+1fNuXM76eXe0A+jTgxVvtiaDUwy6BNsHMlo/zVAN1aVK/rVHH8v5MgG2
         fCAb3JU8f0Anoe5h+17XrxH3fFiDWE2IFYbf97ee06mOUi5BNTN0DoS7hS/ZYCIeXTtb
         qeX/UyRXGtbVicBFJkGXHmFSfgiHJTGnvym/UI38dTbXZM4jjskv3C0jUX5ZswzC/Ljn
         jggm/clgcbw7U0Y1XQGQDXIEhi0WF/+sC6QsYIwYcpZqcpZ9o2oDHObPDBTO542wz000
         2MXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7Q7n0GqXUbm90zr89K7dyQsdhlso4FaG4qOm9CltdFY=;
        b=ZKqpPSqLzep/xndtNV9npepVN9UCrwtng+CYE35d0+KLYcgXEyGxMSRxN8+me9IQyr
         SGkjgS9Bcl1kG26XaYB4loDe8+gVzL4jXnWnGuGX5RQaoOyaOp4Dc35B+It/5xVaXIq0
         DJG/Benv4AZPW/EO4c0fLvv7mmkJ1F2vg+fyHXoUV8oLvzUdrd+Z4/veJHHFoe2JZQlB
         fj2C+X4e8TtFWPXw28LuB2zhQnWiE4CUa+jAWspIPFW1ylVjHTEAvu3bpQMuYa7q8RGL
         ItBCxw8QMJmlphkeMnoxLJoVBFEACmOHOl32KvHaJuGBLP8OJgxkmty2R2a5hH663Fp1
         HLLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVY7xUIPyZWx79AwKLT5q7TsNIzgljwFjhu6hfT998OLWJi3Lyg
	75ntfkEEtzmJ0pT8RThpoJo=
X-Google-Smtp-Source: APXvYqzHIrT/8G1oomgrdW95H6e+42nseafXsFd9852xZTbzKakxKx6YVHpV7h5WWxmpZIBfV4bPSw==
X-Received: by 2002:aca:4a57:: with SMTP id x84mr1261781oia.170.1565696967924;
        Tue, 13 Aug 2019 04:49:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:482:: with SMTP id 2ls159084otm.14.gmail; Tue, 13 Aug
 2019 04:49:27 -0700 (PDT)
X-Received: by 2002:a05:6830:11cf:: with SMTP id v15mr11447717otq.30.1565696967684;
        Tue, 13 Aug 2019 04:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565696967; cv=none;
        d=google.com; s=arc-20160816;
        b=dDsA+UasI7PYtJzMARqiPq6nKcD/45ifVqgSO84MtfRYF0HInCkeDjGMmPCLZjNYB/
         L1hMaH9JSpbuBPIBAG8xEVVZBHHQpWUd/NeNXWJhkjJWXHXRUSLSBrxdiR+hpKDzl520
         CcpANCofONfrazV8j5e1g2hsJHRxJvszJJDdOgXW8I/5JE4wGnubh0WFQeOBA3ot0VdR
         BkWx2+repxow82jf7Mg5jB1bEGS/bzs7iALkUbfrDtqVC5Mb+XA8aw7KItiAUGSH/1Qv
         8iuWUDV5DkfY6rj2bqMn9w+J20H/FoUzBktDGx+Ogbhrw2Kd0nCyC9MX867V0LMZOdw1
         HkuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=uc3mD1P1uGykl4vrf6lyZFb+OSnka2D/oHaxuBykwAo=;
        b=sP40F4PUcIPtcL6If/0pKRnTfBxofXoZhfQ4FPlp+3pvbHAEdLke9gOuZhDkDirEAa
         y5ukysiFfsHwnHbNntoKFISKSqvzRK1ABGmfJ8v1ZGzsT0QQdm9KDZmHaTgC6kqzWd0/
         mov9pHUAVtYZFhHFATiAODIX9m1Qie/bycTTexVnsG9GcJ3DfP7KmL3FVj3q5B15qh+M
         jIOvy5nWWgq5pOECI8+HIezyS6/dqQfrZkoZVXpynZns7gmmq+FpNO8Wo6mU7eflI4Qe
         4vfV3kL1VzTtDrANVsv/WY+iB/dFSNY11SeZ2zo1ujUV32vPYLKMA9nfRqhS550BBtSZ
         jh5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id o9si466122oig.1.2019.08.13.04.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 04:49:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id D5542285EB
	for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2019 11:49:26 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id C97C2285F9; Tue, 13 Aug 2019 11:49:26 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Tue, 13 Aug 2019 11:49:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.isobsolete attachments.created
Message-ID: <bug-204479-199747-U06X4zBRUm@https.bugzilla.kernel.org/>
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

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
 Attachment #284271|0                           |1
        is obsolete|                            |

--- Comment #21 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284361
  --> https://bugzilla.kernel.org/attachment.cgi?id=284361&action=edit
kernel .config (5.3-rc4, PowerMac G4 DP)

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-U06X4zBRUm%40https.bugzilla.kernel.org/.
