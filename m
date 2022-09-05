Return-Path: <kasan-dev+bncBAABBTV43GMAMGQENA3MXXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0462E5ADA4F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:38:38 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id v3-20020a1cac03000000b003a7012c430dsf7885998wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:38:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662410318; cv=pass;
        d=google.com; s=arc-20160816;
        b=i54cIkgrQW/aCZzz+Fw8KeMAU7ENVaEOEe0Ys8hUl1uNo6kirHHJJ80YWbCCnjUsrx
         lLPkI/tVoOaiT6F74yVCaT+cVLwG6UCcBuD4a1dZoZnvlSTOuuh5RuAHz4luvl+Ngk6H
         QWWVcnEyWEzeRIbzsn8WakEspJX980sKFNAKq3GVgNVADmMxNitK4Q70nS9LFNSpUNC9
         fIdJ17WIVm3LbitZZRJaWA/If6BKZGsH+SgCOiKIPbqJRNaXsEb0zd4oIJId24C4hNQ8
         GSU4NYt9ihLnIP9jew7nmQhUi8K0hCZ6CST78lDC7eWSx2+GG7dQLIsh2E75oT/CGuSc
         6X3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=nfY9z8y71XrmnyfAFuPeGKl2zsdZjos1QdE+t5+q/CM=;
        b=HK7SdtcooFf8oMhR5+jqklC8Byn6IspfDCR65IZi8oZFROl4jECeNykHRBXLtrCOOy
         PeeORLXTJ9KOdrOBHGB1wC9vDhZ/gblvTgBv9inPJNR7/t020BCTFyeg4g4Quj7ZXTUK
         8Gju1nBv6mIXZXCGWiw/j0b5rqRD32OB4630jULaOI47E2nlXT/Q/PTfBSh1vNKVI6gu
         IAyQDXWdFBnTUqpe8P+8knp/qnwrE6wcdydLykQB2SUoN2+kgmHfBYI2QuTSMCZW4c/U
         LvceCLta+4xGWbVzLbzNQ5Odj/h8Obvf+rhlsg0rq4FciINrdA4JxFmmTTeWs6zm4swm
         oPPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1aqGnzR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=nfY9z8y71XrmnyfAFuPeGKl2zsdZjos1QdE+t5+q/CM=;
        b=ZTKNLBsZbRLSKtZxtKS/t95dz7FU/XuUbc/j67RYri62yK/nrMHR+NBgO+tBzkOJnW
         flQi2MErW3LkYK+7W947dJ+Z1lIyWFZ/WJ2QCW4bOxBciUgqon34DgbDp0i9kRVGAWxu
         +FLm9h6C5j3HLxAVbzCqTyrIVt33ltamvzFbtCx3BW/ZkGI2BAt6Bhrn5p2SPSfXRT7R
         lz80Ei0CbCHApmSSQYtbORkOZUSthxav5NDUEmEZsjJOVJrvy+jHJtCVxH08ahkgAKLJ
         AXq57unVf2qnLV+29isIOUPRMDssHPshGUr1XOOb0k6XK2l9uAxvlZLgfZJyWUZhvUiG
         1Tdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=nfY9z8y71XrmnyfAFuPeGKl2zsdZjos1QdE+t5+q/CM=;
        b=fnkqolKfT1Btm0JygQbGw/dg2mziHb8Ipe/XZAkc24l8EfTys1i6L4DdXJKIs10oIJ
         8C9iSggDqj04rPkL+uzWjdlMAcjwgt+DgBKiRTtgFA6ib/Qs0Qei84ETSfUCpKlBTAXj
         7hFi4YJDpgUg6SmfLOJKJ+YlN0A3XkK3kxoxTrdRoGvwbccBCBHgKBbvIzKMdCs3PVDY
         +mM4XyaJmI9sIWG1By8zT/X8VDUGAYq6EEYKQyhdYe2H8G1/DR61r6ZgH8T/jQAGUvyo
         CrYz+ScBkmLDcql7daBARKWNo34jL+f8JewBEHdVz8KPryVS9ap4N7GP3PCpW24lB6Nv
         Hb4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2a5qyijV3q403zvszK80TzpaNLmvcXgUjSnkXZ0LCD2MIGCy3+
	QlxzV1d/+Yjkpe2U81K2L1Y=
X-Google-Smtp-Source: AA6agR6V9kXs/iDuavX2RPa1QkoBYvzcF7S6/w4R1c9hwMB7jHi00dHjseG2tHcxmcrSBhSO/18l5w==
X-Received: by 2002:a5d:52cb:0:b0:21a:3cc5:f5f4 with SMTP id r11-20020a5d52cb000000b0021a3cc5f5f4mr26057348wrv.367.1662410318640;
        Mon, 05 Sep 2022 13:38:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls130861wrh.3.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:38:37 -0700 (PDT)
X-Received: by 2002:a5d:584e:0:b0:227:1004:cb6c with SMTP id i14-20020a5d584e000000b002271004cb6cmr10146713wrf.232.1662410317890;
        Mon, 05 Sep 2022 13:38:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662410317; cv=none;
        d=google.com; s=arc-20160816;
        b=i1GkA1DDXd9B9jYARknbWv6DmA8MNTPXisGnxu3UF+/syfwowEO2Q+UdQF9V3Uc5uH
         ye1QTDU1XEOtSpmj2YBs6YZ9W594MItbL0E5S0Ya3wvqBiJhTWDjRP16rD/dXTvcskQB
         TKrRdIykAEKduquYfdS+ElUNLFh6BtHeEI8HQkptrW8Rp/AxBAv6EUnBZ/2ZQn6LAP5o
         P1QWJOL+MQC802xdlSjV4VJcfuCG598nl1KeQl6nWWpF9oFtN+Z4IZLCBsRVQJ2/iWRk
         5AYsxuBFCuyT9SGn4xjDi7uIrfyC964OLxcKajUzYGGHoQxH3IYTyAQLXDD4nRA8Qk45
         uaAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pqyq4icCAPjKFZQ75yWRXMpp9IQVvPZICpOorvrH/Os=;
        b=pqRuGsuU/Uri54hI8I0ZSgdEsDui15692m8mJPXHVdXfNxdsJncXPi5VEmiq1JOBXE
         WB/Z1OdQ+/CE/8iQL59SM+DXiVjqGA8C9HBWAw2So5Hx1aUfxsIFS3N3pbRVjJOgUzr+
         23x2DcK28qA/ZdxH0VgYzwpiEICfDhax5SnsoXME9UYV0hCt7RLglLR5rTvFCINGiLyW
         escbjJ61IVSNtaR2PBa9W7X3A3qyiCcY+0LYZ+ectqljN8knGIcJCUeQrbSEX+CAmt6I
         uCHx6D1gLkbIwJLQ8wS2/wr3OC7Ozknr5mfOQLoOicPbeielDPsy4mdkrbYljSvEQCnJ
         yRug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1aqGnzR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id r3-20020a1c2b03000000b003a972d2d4a4si525176wmr.1.2022.09.05.13.38.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 13:38:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 88BEFB81118
	for <kasan-dev@googlegroups.com>; Mon,  5 Sep 2022 20:38:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 40806C433D6
	for <kasan-dev@googlegroups.com>; Mon,  5 Sep 2022 20:38:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 28BEFC433E7; Mon,  5 Sep 2022 20:38:36 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198441] KASAN: need tests that check reports
Date: Mon, 05 Sep 2022 20:38:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198441-199747-aslupKkNUO@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198441-199747@https.bugzilla.kernel.org/>
References: <bug-198441-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=G1aqGnzR;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198441

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
Arguably, this bug is duplicate of
https://bugzilla.kernel.org/show_bug.cgi?id=212203.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198441-199747-aslupKkNUO%40https.bugzilla.kernel.org/.
