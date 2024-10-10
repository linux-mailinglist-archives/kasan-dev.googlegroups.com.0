Return-Path: <kasan-dev+bncBCK2XL5R4APRBRPRTW4AMGQESC7G4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B78F997D92
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 08:48:39 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4582182b6afsf14779231cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 23:48:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728542918; cv=pass;
        d=google.com; s=arc-20240605;
        b=F8GE1Z7sddJVRAPtdl1VS33mXlEnbpZIbe/uzjXLr/9Rw4ZVYQJ8XecBHj0YM/seDj
         I3Ys1b1h9AU+P+v6srdzUg1cXq8/9A1kbzLIfyZfK91YyoG/aXHwJbTQn5BAUXaGPkJe
         xLBt9GxgAJaII0HulIXV/9UXRk2rxHu4mskbGq+J6JuMsGjYk2NqRFsU4taZT4Z2hChK
         RQOMjlW3kXiqs/uwcyI5GS5xtI1D9i/4mayS4ToXRUt9wd9wRFdsnq2zFDd2mf9BhSBA
         SMMCxBgQ+HN//4Z2BshmMK6FmHJLjgdbCUElDUxye8HzHIach7hXP1R5uUOb81nsf22W
         Wehw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1oTx6bimNFUOCeEqk65W1mOxE0HjqFOuW+BHKz7eXoI=;
        fh=WB2DR1HnZLB4bbGsgg7fxFvfBOlWwWV1zMRtMUNMg5g=;
        b=M3/I2kwmMSoaRsa50Dqtbo6FGthpChck6ZcQniqKBvR0D/EXbOzHH497ntP/WTdQe7
         8XsmbC8YG9+z+ivylSsqUjGLTz88qfKFUu1m/MLRFQBCMWrnCCTAEbTO+/UD5oEk6+3E
         +gsB9+GxfiaCK2eXzz1wdvnkpAqK867p4LgFFfOZTDf9xBZRj4nDulk4kvfPdffSrXaW
         fm24mq/X+NU2oDUcigH/yjMXm6pUEV5rnde3cdj9Jh+gCd/MOCIk3lIBMqpUxkT5USYU
         nak9Nc5YPhcRhMMViK99K3sRN9ooQFl8DnRQ5PlTDZ91QStsyZkpLs3ISdW62BJzfRWu
         b1Fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=JLXBKQfE;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728542918; x=1729147718; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1oTx6bimNFUOCeEqk65W1mOxE0HjqFOuW+BHKz7eXoI=;
        b=MI7MUpATWm0tjNvN1x1mSfOV9RyDn9nZbknYSJ3GNeHe6GZ3YCp1nZlZVsR2nLGgDE
         W54wFues/U1i7EmvLrHM6iL7jHoRobhYL5lOIoz1zaV/2oIYhEXmZTJFMgdC4+kqH1Yi
         C2vASZp9c43APNPJnaz5B3hbYfG4jU5i75l5gQDR2OJyWoL9mgnopwxeZaKQ9khbZpXH
         8FnRcpBXemhodRJZ3MUm+O99hZJzgGV9glqz1ghQDY6BehuEZLv8hxdCH3dqDk98QWnx
         OXcOslZwwq3ezgCzSzkBiAZVOwsbPKwnobppcPAzVf5k1Fvn16YwtO378u1D2EqTeHMG
         NSwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728542918; x=1729147718;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1oTx6bimNFUOCeEqk65W1mOxE0HjqFOuW+BHKz7eXoI=;
        b=GhtXcNbCRbp6zhEUdAkPzo4kuKBsNARgS14C1vLB+W3pWq57uITicZtg+wIFVxK0c4
         1stPEaaHjngtT9ox0+bJfVIFqjobWzUCEiKm+v1m3R3+QlxCwAcRKdP3w08Vf1a2KoI/
         sB5SI+32w6+JiCrbKIVx4ZgW0Nod/in9NBF2wPohxHATaf3bnsAWfKM4QpKXO08v7hdc
         YFiEg8j10xSEwuCq599w4Z8tlfl4peBK/suuPJAh5ynso+YA4KbIUEOZO20OlivTP1Jt
         UBEtDbfhwuFm6MWrnz8vbRwJH/qgQDUKUrd/TEHAyd+lURKnvJOiNOgh2VrfYePWwP0l
         qmIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGuhL+cw7fJkAtYPuvRZTOJ+VYCJd5sNplRvODOxvVGdhP2elcxcWQgADjacYfTqvdr5jBJw==@lfdr.de
X-Gm-Message-State: AOJu0YyvxKfBREsNWLBb30SZGE8U4mwtfCU03tNuu9XrU4+i2Gqw+v05
	Rw5kpfm2Yn7oPIM98utZX4TVvvQqsWdme5CDhdA3qMqVoNTjrtz+
X-Google-Smtp-Source: AGHT+IHVd0F/fh6PDrDZd0nDdXMWYw+3kAt9LENoKZ5lD6cAmnCRXLj30R3fsJ5FBpPLTnuJezuaHw==
X-Received: by 2002:a05:622a:1a8d:b0:458:34df:1e6a with SMTP id d75a77b69052e-45fb0e41f7bmr53741171cf.48.1728542918006;
        Wed, 09 Oct 2024 23:48:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:584d:0:b0:45f:597:8c3d with SMTP id d75a77b69052e-4603fb32e66ls10082631cf.0.-pod-prod-07-us;
 Wed, 09 Oct 2024 23:48:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDBAxwpYr+o0G6X+6arooq6TmdEtqUEZY+d2KWdBbT2lCUe5ej9foYWiGXi8Krs5txO5KYFf7DgUE=@googlegroups.com
X-Received: by 2002:a05:622a:10:b0:458:2214:9c88 with SMTP id d75a77b69052e-45fa5ecaa1fmr82531471cf.2.1728542917342;
        Wed, 09 Oct 2024 23:48:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728542917; cv=none;
        d=google.com; s=arc-20240605;
        b=b5nmJA1+8hbwWGjKD2XY/vMyH171WlYNLHq3de++wfJK1Q8wN17vGHf+dwbXUnjfee
         8JobRlaks8lG7OaTmwCNuzFl2e/iFTHRn2JB5UPfN8ivMaoS2e00SMOCm8VlyufgWygt
         QSOA/VTZeJ1AzKAwul4dN0Q906PyzW3r5jD98MLKr0eStMHPPKvBm0nilge0QrCdnu61
         DTgqDTvtRqxIku4OK4WiOraepQbQlbCubjQ5iZGALdYj47BTcA/oDo25saabC/yrdFtO
         NpYNDG7WM5sfjgu3Ng12zLNNRZQTKyTGb6ZlfI9mX5FyIckJvj7sUyh2n42w+REDPMjw
         TjdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iVsCjrjUVGkyDrGz/5v9GR6eRnt67kS6CddzSgVmS5U=;
        fh=wGrYV/unTx9+xDPiFjjgMngSLlG24W5bPkR29WHrjb8=;
        b=QlyFCz1waoeShXp+MfdyU4QSWvt4MHaYa1uSbDg+exj7hFIP02yRd7HHxJMWMtSarb
         09V2n3bJUA5KyMXldW01EEP7WT9E4Z/IziWXSS294H8F3j61NYrhn8rgpM8/WWjhVvb/
         aS8vrQqXUDF+LWd+fhIgPnRUCDDyf+UAZqg0HiiWRskLZadplep3+xGTzff0GZ3jagwO
         krzSXBKIFQywemOxWLx7+s6REVFR6Yyl3T9k4urXMoHzT9PO/hp2qqBXYgsuWcbqr9eV
         CyoVk9Me4Zr+ZkGFZGfLR6RI8M3uKPgXteuP1mAep/e4/MF1pUY3Ci//JgDUHnrhBLjd
         MVZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=JLXBKQfE;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cbe85a57dcsi293376d6.2.2024.10.09.23.48.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Oct 2024 23:48:35 -0700 (PDT)
Received-SPF: none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.98 #2 (Red Hat Linux))
	id 1symyN-0000000BjJc-1SeY;
	Thu, 10 Oct 2024 06:48:31 +0000
Date: Wed, 9 Oct 2024 23:48:31 -0700
From: Christoph Hellwig <hch@infradead.org>
To: syzbot <syzbot+8a8170685a482c92e86a@syzkaller.appspotmail.com>
Cc: chandan.babu@oracle.com, djwong@kernel.org,
	linux-kernel@vger.kernel.org, linux-xfs@vger.kernel.org,
	syzkaller-bugs@googlegroups.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [syzbot] [xfs?] KFENCE: memory corruption in xfs_idata_realloc
Message-ID: <Zwd4vxcqoGi6Resh@infradead.org>
References: <6705c39b.050a0220.22840d.000a.GAE@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6705c39b.050a0220.22840d.000a.GAE@google.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=JLXBKQfE;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
 does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
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

[adding the kfence maintainers]

On Tue, Oct 08, 2024 at 04:43:23PM -0700, syzbot wrote:
> dashboard link: https://syzkaller.appspot.com/bug?extid=8a8170685a482c92e86a

[...]

> XFS (loop2): Quotacheck: Done.
> ==================================================================
> BUG: KFENCE: memory corruption in krealloc_noprof+0x160/0x2e0
> 
> Corrupted memory at 0xffff88823bedafeb [ 0x03 0x00 0xd8 0x62 0x75 0x73 0x01 0x00 0x00 0x11 0x4c 0x00 0x00 0x00 0x00 0x00 ] (in kfence-#108):
>  krealloc_noprof+0x160/0x2e0
>  xfs_idata_realloc+0x116/0x1b0 fs/xfs/libxfs/xfs_inode_fork.c:523

I've tried to make sense of this report and failed.

Documentation/dev-tools/kfence.rst explains these messages as:

KFENCE also uses pattern-based redzones on the other side of an object's guard
page, to detect out-of-bounds writes on the unprotected side of the object.
These are reported on frees::

But doesn't explain what "the other side of an object's guard page" is.

Either way this is in the common krealloc code, which is a bit special
as it uses ksize to figure out what the actual underlying allocation
size of an object is to make use of that.  Without understanding the
actual error I wonder if that's something kfence can't cope with?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zwd4vxcqoGi6Resh%40infradead.org.
