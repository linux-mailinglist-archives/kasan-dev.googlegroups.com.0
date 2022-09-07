Return-Path: <kasan-dev+bncBAABBKMN4GMAMGQE6BM7F5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 186665AFD4A
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:22:19 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id s24-20020a0568301e1800b0063b341613f2sf7648942otr.19
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:22:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662535337; cv=pass;
        d=google.com; s=arc-20160816;
        b=LT1pQOFdZa8xm+tXbyZ/n+rpoo0WyD/kFkuZ9lGDIU2HcYEnJ7nNebw02TdFDahgaE
         G7ZpErvU4YgOokzRTjSS2OuJBjHgXf2lv5XFOB7hvFs7CZAQTlRq9F08RwA0BPOCZQIy
         SGIFsFyNVvFgSBtYS+dOprOmKlkYiAGlg7QguZOI64m/f2foDuVjchkYY/+yXB25bdZM
         5CRYd2fAoHrrK67wJQniCDDR7aOeX0f0+TNXTMDXlwka7QjXX/iULyohKjjtyS5KpOc9
         hXXzs4Dlyl6oPh9Byyv682fUoWrsJe3bD3SbCN19HrCijLovd7vdEErNqyVSQP2JAEKy
         ZyRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lREc0voT7zTo7Gnn3NWL1VGVVm5YDi4+inbFB/8R0oU=;
        b=V6dFupokfljRNQTk0/hGwOfadEIPeEEu6S3teM4wUN8bAZxAUHQqOm6z/LZQXoUMjM
         SggaD8pkYu2PCAg+8W/GVSRhZdVzmgcDIwqHs3LtM8tlh5reLEc82DjHRPV2glHpRfQ1
         ir80cuxvnoDbHYlPMOJitNXnkW46anFRjZzRPTByzxZ0HrJFwdb0FV1Re8dYLC+3mRNm
         XrAnN8mlsNbdegT2FtoGWO07OpPUT1GLzZ+ffWofRjC8Hp2yRxeaBedKisrlnClSSoQY
         tFj763O4mLf4efGyEFsaeKvUDgzKvNwNZWZ/tfzkZSy9nPx/fvy+Qvb6c1rqR3SqBLqx
         7pvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TcLjzBaF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=lREc0voT7zTo7Gnn3NWL1VGVVm5YDi4+inbFB/8R0oU=;
        b=ZkA4mF6BH/vjf5gMFQipgFWZthtc4Bquz6IG3eFhZlfxFC6+uIESwr4ezL6vnnzTtN
         HPDrIOR+SEu5o8q/JVr9UIA6BITxnsh7L+pBfNFNL6yDtJTQeH4IJwpTYZztpV+Zgp5C
         OGbY7nl/RoXX5ccyTDm5logs3HEnz4oMSEvJVxd5wjCJuenHL6oGCLdoIvRv4BLmJVF3
         bdpxMzQYCF6Sa62DrTwztCMT+yT6Id75OvgRKvNVkOAmcdTdBVoIDMbCEeoMvvtnK+i5
         fK5yRXH1dHubDYThgSMMjnh1BoKwMrJjjYYSrvK/5Vo3JhGsVLZuZHjtDcEV43guGlaU
         7mRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=lREc0voT7zTo7Gnn3NWL1VGVVm5YDi4+inbFB/8R0oU=;
        b=T+lKfgJw2BZ+sNDloxVHT+sfrF5Rf35muyT3sBFI5OUFgaWfNmHmNhijQ8ZdDsKNIl
         eLMGIR7qg3Tqc022jANtzbUr5eoz/NeHtdzLaRvMa12FI/hHMAhhFmaYXaQRF8iULcKu
         YEqUKPXxmIE8QGa+efNC/b6Gjik/JSQ6Pd6X2xKS/JNa/DScILfY/vJGdMrVwsMnbTzq
         rXb68ABH/QGZZIVcuB4Ro+7iFzkdeST/M39UycBxRgqHILHs5sXS52pf/95+38cYYLIi
         cY3ziNrHCcFkKlmfODGBswGizigb4JYA/Wur7UurTNXun3ofbA7qXFomfMflE0Bjh6lI
         7Rfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1ylEQJWw5+D2pPrRKxBroS44zOzNRP8p5ErrBnc1CH46hQgeBC
	QNyyQm+zdHwuab64NaUQ+jk=
X-Google-Smtp-Source: AA6agR6/fF0MNrzHfumIM7Qk2PYBITATx1R0rEQ1NH44WupcB1DFp1rg/7/SUQfzKoYJw7hmXRjzTg==
X-Received: by 2002:a05:6870:4213:b0:116:de05:c63d with SMTP id u19-20020a056870421300b00116de05c63dmr1140123oac.141.1662535337634;
        Wed, 07 Sep 2022 00:22:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f03:0:b0:342:d439:fe70 with SMTP id e3-20020a544f03000000b00342d439fe70ls5293108oiy.3.-pod-prod-gmail;
 Wed, 07 Sep 2022 00:22:17 -0700 (PDT)
X-Received: by 2002:a05:6808:6cd:b0:34b:73b3:416b with SMTP id m13-20020a05680806cd00b0034b73b3416bmr914293oih.196.1662535337270;
        Wed, 07 Sep 2022 00:22:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662535337; cv=none;
        d=google.com; s=arc-20160816;
        b=T/C+dUfFUVNIKPZ1hFfnacSEl+PYNwqYXGFGP5mQffM1LRBydect+aGu1F7Ku2E18+
         LWvYHwdvDFB3y0kfjyNB74ydsoUeHVRGGuCr9TxRYkCjaS3h4N9ZIUl8kIwTtozkteTk
         bVfTi7Mx0nP9tpHODaY9BIefignTKtZpfu6B1JfhSDBMkX6XfyPMi5Ts3ZjmJP/aI5vC
         MsPXgt47JlvtEMtdZy2Ypg/TnIMYw5w3ToTYBsl4Qw6Gd7UageLwIUm5jH4G3QqFqaVa
         NN9hzNnucFB5+WMOqECY4YtwCnPF0cEDbvFnMX+T1SohY/OZ96ctgqxgNmyc1EZKbonr
         VjtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Gjh0f9S7mAMNrFp53O5XdvhfOIGxXtiSB1S43xbShfk=;
        b=qjESNNHRI8q/hhTQuYSuoYl3CQo2Ui1YWMIBOHF8NDAfC28Bba+1jiFIKvEv8xIjMp
         TwOmeeZbpfzoNlm8zQ0G9/msCHCy8aVwUTUJ3R0zTaAHW1TQI3/6KorqRCxyvPPfbVQ1
         iA9sZ26Wge4yHiBjInFMrS5oQK0ZquFnXGuZFGzVrdrYWmk8WPcJBdVQGsjh/0XoLFm/
         1FWH2/7uQQ8WqZ/GC2QqYo4fTi1VKtsoHfVfzCuK8SkyoMM2Lc8z22THjj4vspyPs5VJ
         ACMJJIIUV5fcNIrbORDffPrHEkaRIPNH6jAmzfC58G0i3TBWZFmbWPaUJVTtas0VBfpO
         Ru/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TcLjzBaF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 88-20020a9d0161000000b0063948a79f62si1624055otu.0.2022.09.07.00.22.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:22:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 076EC617AB
	for <kasan-dev@googlegroups.com>; Wed,  7 Sep 2022 07:22:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6EF7FC433D7
	for <kasan-dev@googlegroups.com>; Wed,  7 Sep 2022 07:22:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 55ED8C433E4; Wed,  7 Sep 2022 07:22:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216457] KASAN: confusing object size description for OOB bugs
Date: Wed, 07 Sep 2022 07:22:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: priority bug_severity
Message-ID: <bug-216457-199747-xQWFj3IGtU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216457-199747@https.bugzilla.kernel.org/>
References: <bug-216457-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TcLjzBaF;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216457

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           Priority|P1                          |P2
           Severity|normal                      |enhancement

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216457-199747-xQWFj3IGtU%40https.bugzilla.kernel.org/.
