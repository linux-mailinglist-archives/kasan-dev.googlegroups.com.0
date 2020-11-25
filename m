Return-Path: <kasan-dev+bncBC24VNFHTMIBB6E27L6QKGQEHGYZPKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BA352C4625
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 17:59:37 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id s8sf2926380qvr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 08:59:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606323576; cv=pass;
        d=google.com; s=arc-20160816;
        b=mcA1WffRBIwWhN7TqBFN+XmeaWt8NIZ/NKbN3kOznz4IAahyXjDj6D7CaEyZbNOs5j
         dOzVW7Ey7vI6BO5RPTE86W2W8SzS8VIvm/8uIFM71AgO/izpNT694K0LaIXeNUu8dUZQ
         LjwcMw+VwMcqgKVW4JKvZ46yIa5YJ1eyL5FPJSAaR2hXXA7HoX8F/K8BnS5l7Y1FS1cr
         PFkDzVy77ZuEAyQ3R/FB7oYnghrpKIik8QdJvZSkAW3ga70JO0bnuxxeV0G4tDbd4vP7
         bHuCKx8wHTZb7YRpU4+Jw7rDGU5T/wSd/agFchfehS4ICbmdmx7FmX+3RUaZcMGmJ7Ci
         YR0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=euu2lSnDn7Vv+0DU8/78vWVtsUmuKV8luFMZ103R264=;
        b=Vz9UbFKzpAjzu7idLUQjZ3wZIu1UFuPJrWPx+geJHtZqMMZ7OgAZGHEis0iAHIC5/S
         dvotKuIxlMBmsOi/X2jRZreJ2J67KSdo4iFX59xIQ84HrRAAtnVzhIG0ATLAtRZtl1AD
         E6Pj8MP2uIcHxmNuVqBEMR0JNXaLOJzwl+pZWypgXuuKSswLu2S9Yy8Ko9vQTrheTxOD
         aAqkb28jRLZ8/fXDcSFV7956sazkpW914CegeJ3KERXW97QpBOn79r7jY1Cb9lw2mQwx
         7oQ9VuS6IxTP5UnFEvQp15LjZtuDW1qdRH6sGQFR+iVzzby7Cw2zZrHfba5Nr2ehsFig
         ByOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=euu2lSnDn7Vv+0DU8/78vWVtsUmuKV8luFMZ103R264=;
        b=mXnbRQz2aKAFT/3HcLL+bx76JHODmL7D3KfHqjLY614jVRV5cne0FjkAbWt82l/eTD
         fBxLk3chd9upjCVjdzXv0JvcFoS739Zg/pyC9KpC/D1bZr9mpnmM+N3169nEo8rSDkzq
         0rnlluB8VtezGXDky6qc1GqBnobTHBkhyBx5ssYrgOQ+wOqyl5zkK/HVQNuwvS0bBbXS
         WGXQQBU3tIKACXdBkyn4OMCwTDDSJSwohz1PnfEoqIg+F8mMQed7P/muk+mZL199KvbC
         m9Sc83I42GmEE7mRE33MdCxVcHGYUTmIgZ+VZJjaJaZZi7jAzYISbG6RMg9IkpshuprK
         K0Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=euu2lSnDn7Vv+0DU8/78vWVtsUmuKV8luFMZ103R264=;
        b=tE4ZBKzLk0ZOnNkJn3Ocdcu/fymeVUmUptOJD2IsghLlu+bP5ymkva5Er22UpJbani
         u976yfTpf6cX3QieFV6tLAN0P5hdPqg+xV4W3XGx7Gh7PqI0Ch57osqdCB+vI6hVRaV/
         +BR2jGuLIkLASiCntXh32Xcfuiv1Wk7sYvoElX2k8a8scC+i7B7ACNo4KUx3qXGUyzcl
         6lNWjmRJQ5UMt9zqCRwILYAjmaXKIcAluozVGAkmdCNUUIP+KzTPEl1vYBuMbZDl3CpK
         YS1FL/at7R6Vf26kzeoaVHACBuzggkL7g0Lg883vouP/MgcytjXXCgWfkiqipyJSdSBu
         vi5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JZnHQ06EJpIbKHqndwavh4qtoH4c5uRbVzcvwUk8Ek7de8Vft
	XjKI7Z7FfDnpAJZ7ZRmFaY4=
X-Google-Smtp-Source: ABdhPJzmY/GxjBqjPuwie7LmHrsgNnovZZcuW+h4bz+PMwQu67+wu1zN2F9zxTcUrBKSWhl7q2ek0Q==
X-Received: by 2002:a37:5103:: with SMTP id f3mr4160601qkb.460.1606323576452;
        Wed, 25 Nov 2020 08:59:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:2795:: with SMTP id n143ls1309685qkn.9.gmail; Wed, 25
 Nov 2020 08:59:36 -0800 (PST)
X-Received: by 2002:a37:606:: with SMTP id 6mr4274043qkg.326.1606323575980;
        Wed, 25 Nov 2020 08:59:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606323575; cv=none;
        d=google.com; s=arc-20160816;
        b=SZ2neUSr/e41lbVXuAEr0vuSHbEqJJWX+bD4v4MT9QHXeYR9StA6lVegdBJz/wnI3/
         7VeCB83fwb6s+ZP0K3CWgbb5Enc9+yOJfOO6xdoRjlbQ9WbS5d2bgSmhzuxFQeh7mjvs
         MssS4e/1gWLLQdVSbOp2xDKWHbchCZ4hrVc9zkUwouk+pR7WHi11zt8CgvhdmVrVNSUp
         MJpYdqSKDD9wzO4o/9XywMq7D0L9/w3ggAoY1I8+xOH83kpntm0ZQR+rewNEimrgfdTw
         Lsh7zrlk2swnraIPOO5s3CDcumG1pV2lWB+J9yB8voY3hbXnw841yaXfKX0p9SymUO4r
         UH0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=F27z+/gY9+joJU3/MZcbrEiFmtcky2WvDuVnxVDDW14=;
        b=oLaMQ+3AOtv7Yhf/ie8EhIAaknkgOVzBMD0orwydZrSyuE6zRrirdiAeTrdm4CciL5
         o6lZv26rZAB/wHC8Pjsv+T6451XSKmZeYKOtvNDLTfjG/uFoNw3i1TuLD79fWx3isSB/
         F7BaFI5Ml7Qmn1al3jL409rDtG9+AApu6jSkSsflytSQAI58ASLQe5qq3ZHTSOfZBuMr
         Myz0VXZT+y2W0b4djKZ6x0Cd2r1d/ghbJKEdYFhjlFgBmAuJS8VDhF6CjQ8s9wHj6i6D
         EGYMPKGUgbvu/uKKhRbNtcNmiNiwm1uULgB3c+iaQuLjgBgGx7nLeMGLuzzQZi62Ic1f
         sRGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v74si143218qka.5.2020.11.25.08.59.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 08:59:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 16:59:33 +0000
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
Message-ID: <bug-210293-199747-WzLw1qQylU@https.bugzilla.kernel.org/>
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

--- Comment #13 from vtolkm@googlemail.com ---
Created attachment 293813
  --> https://bugzilla.kernel.org/attachment.cgi?id=293813&action=edit
accumulated leak reports

attached accumulated leak reports since node's boot time (~2 hrs), accounting
1,976 such leaks

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-WzLw1qQylU%40https.bugzilla.kernel.org/.
