Return-Path: <kasan-dev+bncBAABBF7TXGMAMGQEVYBFIJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 195155A6EC3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 22:57:02 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id j13-20020a05620a288d00b006be7b2a758fsf6278387qkp.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 13:57:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661893015; cv=pass;
        d=google.com; s=arc-20160816;
        b=rwc2R44g43Jv7OCkl9KUz9NkSb6+/gMuu6/ZlcmEQaxuMBacX6avfnCGTqtCU12jRa
         LTuUta14BAcbgMi8Y75ZwEEylFjiNXvaXiw1a1f206wxNUG/PkQTPi9gRjSwS/hiv48Y
         WzWQDIIzMfsv5ZAhUmWWX81wVVTQH9GWaYXmr/druu3V8PHuRglF+5js9G/xqst+rWQH
         eQxnMtRsZMa+rrupPsKZqGVTA9ftgyMAGHweRVbcU/bNKzbUbrSSj0Ds5x+Fwdjq2CdY
         s72pSwSKJbNphpU8S9Z4BwXzzdA14UZbAGKCshnbLZbZMMow25V/HZSUYrLwmO3BJ/VO
         aDeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=wMZvqIuHYgfr+6XRC0WuI9ISSeO/rV3wseoo7/m9nAM=;
        b=qiZC84/7lukuRUIM3bQvAhibNNddW5K83954jHz97ZvQQJiAqOCj3mojK6p2V7yKoX
         XPdyf3fJsZVFQq5r5z781l+K/u0qh65Rbl0PEVhoGWH2cKTvAUoPuaqK3dcPPQqc/kz1
         3YRIs8e4guUFgFygGCNENdUquAYAIWdmHfiORrTlvc3TMwZLptEVJHJrvUetfJy7e8cW
         0RDtuUl4IJt0MHcDmmawUNNSpdFsvRHCYZw2v/r8lLCkrhPziItBeTWud30QceEPM4Wf
         +KS0R8rgH8F9Cad05EU8yJEitkxyCA9ByN7uxcDvtm8qmVFHGWUD5ATVDsJFeI7Vb218
         iJQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AeIA1SZM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc;
        bh=wMZvqIuHYgfr+6XRC0WuI9ISSeO/rV3wseoo7/m9nAM=;
        b=fqwmc4C1CM7rT2keh9mCfrHV1iiBJjdjPnmOpHFNfs7/MMcxffOQS1vW1zMGaqQO4v
         nQjt81EymqYtWvHCFL4MVsqpnag53EqxziN2DOviOM6gkgKlUrntNzTphDnLCQQ9GMBe
         vTAKqNd2uM/nIXZI0mtzyd93t/Jh+H8i2R86HbS0U13ZnuQ7eMuTX14hKZyCLjXOcJ1B
         CIyzT1SfmHNtlBJRB0dbZ8xfPv/UrWlk5eCnBde10m1JvQ2KyuNZM+fYiWfTH0cm1A+r
         LdW19vGk+xnAS7TsRk6oI18GZ5gnbzBttP3SNE4vLJ9rcGyIKOX1m9/JrE+nRQMfZWdX
         Ga0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc;
        bh=wMZvqIuHYgfr+6XRC0WuI9ISSeO/rV3wseoo7/m9nAM=;
        b=IJkAId0GpepiGwj4lmdWqM8VX4eQMLYbWI3qgCdRRhEldHcRyO94oD+KzAffvICOIq
         TIZ8jBKlsBBemRPUrNYsKRmAfJRs8WCAn9F1mrIfsX0O5m4MbVVs4MAcqYpgs8Zl1+om
         Vp7ovTThPgSmvweUXTVIs/DPT5dnWamxn2dQuNRgNVz7lMdNlBFFrm2/PVad+OEvj6ee
         Uj/RouXfpoDyX5P6XBZ/WdGlRVGw3K2YcxUfkHsLi50OH8zCzl4c12RqtSawJiIsxZeG
         U1nwkbRiU3OKXNM/d1Ds9/7pbxW4eyt0VG7oLbUwibNr8jFn4vxUG0UX8L1u2Fq/0e0W
         +6Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3x9rfwAS4Wka2w074MjaiqX4XP96fo4bk/Ico9v32mYiIO6BRs
	4T1BTpmxAVa+31G1y4SEz4c=
X-Google-Smtp-Source: AA6agR6RJUjCP2+gVUtRMFpxyu39HZCEJSjlPrlY34g/iH7hKFDuPGIl9r4MRk+oLUr/dcRZ9uq1kA==
X-Received: by 2002:a05:622a:2c1:b0:343:550e:d7fb with SMTP id a1-20020a05622a02c100b00343550ed7fbmr16104045qtx.286.1661893015309;
        Tue, 30 Aug 2022 13:56:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:70b:b0:6ba:be1b:6a6c with SMTP id
 11-20020a05620a070b00b006babe1b6a6cls6769618qkc.9.-pod-prod-gmail; Tue, 30
 Aug 2022 13:56:55 -0700 (PDT)
X-Received: by 2002:a05:620a:2545:b0:6b6:6773:f278 with SMTP id s5-20020a05620a254500b006b66773f278mr13616318qko.390.1661893014933;
        Tue, 30 Aug 2022 13:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661893014; cv=none;
        d=google.com; s=arc-20160816;
        b=0+E5j5WY1qO0CIwxmNUc5kCVijnkzaPtE2UQQQRHjEDSi+aC8cJPXEcKWHCTrPJQAJ
         ceTBuslWRWOGz1h7z/wKnPuCvUSqo21NQCo0SuByVhabvlYkn6rHdzlJuehEBo9By/Yd
         KrAma0RmGOfiZqxD4N0jkcqSXsD5YWkyjwEu9PftQC69TUmpKQX6g58soNDSha5+XkxM
         fLbCVypW1FWnKhLCtWb4Fy/vY9FNrC8Ld2FKLrw5itexU7s7tTUulXLhK7PTMnHtPPkT
         KlLi65T4BdBEetcsjAdv0mAdTp//USROKZMRA+iwwVmu89+9qzkZTnsD6SIJsQLbHtBR
         6sww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=eiR8FY3Cfna9xUGQzfH17IOveuJpWIcWGIlhJ1rJSDA=;
        b=i9xM58PQbFVxXItWCX8va1UR1kWzIxVOr2sXZjfsRiVSP3HykN7W4SptMjRVo6WxMo
         u3pxLX1du2R11UYk3oa9l4g/YG/zawYJt/QK79NE42KQGcHhhU1IDxqodDLd7YMkyC0Q
         4Ji7e3qY0eP/KRHZDwrb90ODj1ztzmGP9afRaLEXVL35tpjTip/ySWsLKUDnRhnYfUW3
         jtdLkUulKLESLRysqpeTkxlE9MgTqrDPoHQOMKuJ9lHIC/tun5IQv1cGfz1AdQd7vUru
         SK21CMO/wE3b7URRhsP1tEwQYtvSeB7plqcO6dkTxq2nzZRE/qdc7fPsJSwCYxBpQpWn
         b3xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AeIA1SZM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id w14-20020a05620a128e00b006b95a1880d8si374840qki.7.2022.08.30.13.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Aug 2022 13:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A47E861523
	for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 20:56:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 17422C433B5
	for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 20:56:54 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id EEEDBC433E7; Tue, 30 Aug 2022 20:56:53 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212193] KASAN: better invalid-free report header
Date: Tue, 30 Aug 2022 20:56:53 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212193-199747-7hpVY3IPlv@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212193-199747@https.bugzilla.kernel.org/>
References: <bug-212193-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AeIA1SZM;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212193

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3de0de758029a0beb1d47facd3d390d2804a3e94

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212193-199747-7hpVY3IPlv%40https.bugzilla.kernel.org/.
