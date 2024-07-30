Return-Path: <kasan-dev+bncBDK7LR5URMGRBZXPUO2QMGQEBVQHWEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E31941448
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 16:25:44 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5a161d546d6sf33859a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 07:25:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722349544; cv=pass;
        d=google.com; s=arc-20160816;
        b=lfkne6i3IT6QP4UqqZS5FbLcpu98KDLh3B+d+xJC83ntVQQZYf0lJLUnLq7WlipAQR
         /MtPUsqcJQGQ1Keg3lBeX0/5iKgjK9KABFODCB+3tlDGTKXUyT1N4geRvETVXi86zmA2
         Rg/qSFdOBLdDbLoIhknViLttKWi7uo9qHfnpD7Uba/WQITioo+ey18BuGIFq2ryQTInR
         xS62APYwlykk6XjDjtN1kN7bfZsOnfF5AJgxwOCUj0CvMFj13tBAAMCRx4TiclHxCgIR
         5Igxu2i3nQN1duMfgk09NEo7XMRKpuXjesYYP0CrjKIzdELIPr4gWYQPzI4alLI4X84N
         PP3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=41s8uekOMwsbumwk2Cg+gv0Cik+bkbCRC7n6Zb2p9b4=;
        fh=FakmG0JDiExuCzGYGlvxYjDLEwJv4A+p8gzpIPN5oZU=;
        b=g3I04heBeBI8Eo5R6NkKkmgP8OBkQj8MCKx+Y0A4axiOYkVhqt0edqgDGx7ozyWrn2
         o+boZLCSipztNSah3RD+vZSe/hFk2R+8arkFSbL3L2JucnW4HVuGmuzbz0+759gIrzSV
         MqUhQ71nubuAB1411tVl3szUhgs9bLTozZsuCiE3YPxCKvyF1SgATesDeIgX4OSJmo2o
         Dw+B60dosO7IMIEvCRMT5OzD69V/LOoNEA/RzcFfKcicFwqCwIVoxvThyptF/CsOCRFU
         2A9sWkK0qNmReEw3/DTpfF/WLMoi18AB2fYMhJ0IdDFTj3jpqS56ZDVFgxqkClFpm4E0
         oQyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=becJiEzW;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722349544; x=1722954344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=41s8uekOMwsbumwk2Cg+gv0Cik+bkbCRC7n6Zb2p9b4=;
        b=XDP09Z48F/l3aoYPLWQZi6Nl8tW5zowwn5cVhRdo2j/moEoQ8vSnuErCUnJtTRrDmd
         8cVCgS4PaZXmVxxzRjsK/ELibIAOVlNodsaeWOYqnxsMrBs2jUTLDvSPaY1dUh9OOHxF
         USb21NEpds2lcqcq+g0DtWHi02gqd1B3ERM7OoSAdp/KoPz6MT3T/eYOKXLeNHvyVBxF
         H2BZNDKdvLSPrnGLy//DEjf+AyugA2DY0B3M8Wf7MHuGAGMfigXVNPCGEMoAjk+MTWWP
         iGip4aoiweRDcRz+WfE6ykzOS/cwhQujvqsUsErCgcEeIF7JGA/kwPn4ut5f8ZeemTHM
         zlyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722349544; x=1722954344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=41s8uekOMwsbumwk2Cg+gv0Cik+bkbCRC7n6Zb2p9b4=;
        b=RaYp9N5Mcu/FwZhXgclnzo8PQzyTxNfEjn7fWN/y2oUFoVNqkuU1jbuL+De/p6XaXB
         +rAXcZmF4Y8tcDs4a2bDX4iLE35ylXeHT+jAfa+2C50JpH/nydc731nSuEYyMjj7XAkR
         /SlSgXw8eJuB1eyh6p+Vk/wrVUK7eb3zPDN1EvkInskbkJcoLqmCPvg1NplD5U2AEUMf
         Oycz3tshk1Xv+EIXTPMucd3x/qKIWBbC1Wwj737mwyzk4mfleDBu4/MF2GKWFTgDcEvc
         pugVqIb4LuidSn5w9YvU+TxcmY54Y2cAcgFr6REnTpFb7nyhCH5+seE8IKrwzg15tZDw
         tpKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722349544; x=1722954344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=41s8uekOMwsbumwk2Cg+gv0Cik+bkbCRC7n6Zb2p9b4=;
        b=Rwb8KwWYBrEX//iamIf6LQBtwY/ICmctSchs5CwHzm3OX2ctdxOt28CBKwBlj0F/ri
         RGTsomU0y6N/XUop9nwJks4wWmyl9f9buS/M7K9Q1JAkSb0SHoetqAUwrERdZFTq4She
         1423ZfQWTcefpRI5IVUXcmOjvXJnnQD59HC/kIGsKnV3UfaAhqUgj3ttMlG2UPqqU3by
         gA5jiI9HJLOzhjMLasXPfv5Y6qu/zD79jpUcxBg/Hz7KwHz/uQAOOuhlXw3SNpXI9BKh
         jH4AnSlPGwCazpxv6phJPIM4sdBxpPg93PkJASof8Ie5SCiKxylbkWJCWinERgaSfZ83
         eOSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdM8ED5zQz5KyNQY4HvVH02Zl8/MPJpzHab9fE6byijbnJN0Y/sNUP1Dza8AgyMDEUZZiHE2ueKGiH1tSfsvSQH1DnY05u2A==
X-Gm-Message-State: AOJu0YxrO3BCia/2DsEKAxeAZcH4FqeggqpmogtZW2H2ZDn18MtL5jVg
	PjebB+LZstHbzetFDUbycMbpkgNyUGeuFbl916zC0wTXkdiQClRj
X-Google-Smtp-Source: AGHT+IFg0c3CMlZDKGm/PHyYE7Wa6sEJMWCJeNQtRs/6AKNQB0idJIA+qmWDLdxcBrK3lps0sHivRw==
X-Received: by 2002:a05:6402:5107:b0:58b:b1a0:4a2d with SMTP id 4fb4d7f45d1cf-5b4870fc68cmr95604a12.1.1722349542562;
        Tue, 30 Jul 2024 07:25:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2104:b0:2ef:256c:a268 with SMTP id
 38308e7fff4ca-2f03aa9eaa4ls137161fa.2.-pod-prod-07-eu; Tue, 30 Jul 2024
 07:25:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxCkcm0DhB2U9uCL/tRgFEEJ9UApDo7FdqniJvdRVQjEjMnJPtJmtAKhinNODbGQHQM/GPyrtfjScuGLq+E2t2Cxe2TEHKURYJqA==
X-Received: by 2002:a05:600c:5492:b0:426:5fe1:ec7a with SMTP id 5b1f17b1804b1-42811e41a81mr76822505e9.31.1722349527176;
        Tue, 30 Jul 2024 07:25:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722349527; cv=none;
        d=google.com; s=arc-20160816;
        b=thVMHvmCSC8boETujvBnSllMMzv2DTNNecDuNRsVlDXVlsvrELykKmB6C1hLTLNN/t
         WS0RpX2MexpLn+DxES2ukyRvFO6cXE0fl92Jk4t0/iOCflr3o4WHhAcExt6RimAzd9UN
         vdSmmeQsu87IE9BH5NoIwicSFuDzyfVsaLvHYTroV3uQjByQXhntQHt+PxMU+LuYhL0D
         sOn9+0qqSalC52KDxLlw1u3Xm1prrC9w5Sok88f5RwGtZWPKgVqmbrrZ2A/LUcMZv1Hw
         FKh6jg8ieKShKbd2LhszsgxqYln1clWhYEsObrXL8tqphGyE/cFIf4WmM0EBpCKTnwkd
         bugg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=5VQEznJg84i5ZK7eGARok4l5wc3m0IWj/uMPsa8F98w=;
        fh=8GlScaSMS8FfpYE/+vM7Y3r9QYMzTewOFQNTZhKdQqQ=;
        b=IxgPsE5++5NXR99RuxSg/p9UXFFHNPMz2nV6qfzz1IfeX69Aa/5HAfQkGLz7Slfumd
         J1dGoc2X2djJoBn5T76oMZ76tnswev4uarRy+8P5uNFmWisWtxx3/7VnbL6qK4q80avP
         oulCksMBX37Hu1JCNg1XLoQUNpAfzAfxZxkr3+t4fX/qStx+bTo6vl/AqWRkfKSB7ZEa
         zij/ckqH8cnO+grd+Qx0YvQCr6ILLhV06w4NxCUkmxQ4Ju/upbQDGDZfl6uep7shL7tC
         0Gv+LfW5WQUwwEbmwRpFYFFxrJHuaYVRPNZdoWin+Zvlk0lSLjGLwQyV4AnhqAbfhBLW
         +E8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=becJiEzW;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af684dsi1135325e9.1.2024.07.30.07.25.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 07:25:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-52f024f468bso6949075e87.1;
        Tue, 30 Jul 2024 07:25:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVrM/dkgu8QQcfn1H5Jq90JBFqDMMgCav2yUx2cGpmPmTsRKQQl+exaq70/EE5JNFDyI5Xeaf/G3YJyC8VXYPVOacz+o6SoUcAnbKdfQg4fsrvChBmiesegkIgNdWjKd6idqN4Mhs7/J6oEg==
X-Received: by 2002:a05:6512:480a:b0:52e:be1f:bf7f with SMTP id 2adb3069b0e04-5309b27b283mr6293800e87.27.1722349526121;
        Tue, 30 Jul 2024 07:25:26 -0700 (PDT)
Received: from pc638.lan (84-217-131-213.customers.ownit.se. [84.217.131.213])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52fd5bd15d2sm1868898e87.112.2024.07.30.07.25.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 07:25:25 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 30 Jul 2024 16:25:24 +0200
To: Andrew Morton <akpm@linux-foundation.org>
Cc: syzbot <syzbot+ff2407cef5068e202465@syzkaller.appspotmail.com>,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	syzkaller-bugs@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>
Subject: Re: [syzbot] [mm?] INFO: rcu detected stall in kcov_ioctl (2)
Message-ID: <Zqj31Kf9_Nb01GYR@pc638.lan>
References: <0000000000000f67c9061e649949@google.com>
 <20240729143112.3d713abe2bde51d718c7db93@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240729143112.3d713abe2bde51d718c7db93@linux-foundation.org>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=becJiEzW;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::129 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 29, 2024 at 02:31:12PM -0700, Andrew Morton wrote:
> On Mon, 29 Jul 2024 08:34:33 -0700 syzbot <syzbot+ff2407cef5068e202465@syzkaller.appspotmail.com> wrote:
> 
> > Hello,
> > 
> > syzbot found the following issue on:
> > 
> > HEAD commit:    3a7e02c040b1 minmax: avoid overly complicated constant exp..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=132e32bd980000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=381b8eb3d35e3ad9
> > dashboard link: https://syzkaller.appspot.com/bug?extid=ff2407cef5068e202465
> > compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
> > 
> > Unfortunately, I don't have any reproducer for this issue yet.
> > 
> > Downloadable assets:
> > disk image: https://storage.googleapis.com/syzbot-assets/198814da854c/disk-3a7e02c0.raw.xz
> > vmlinux: https://storage.googleapis.com/syzbot-assets/868e99275bc0/vmlinux-3a7e02c0.xz
> > kernel image: https://storage.googleapis.com/syzbot-assets/ce63033f3708/bzImage-3a7e02c0.xz
> > 
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+ff2407cef5068e202465@syzkaller.appspotmail.com
> 
> Thanks.  Possibly kcov_ioctl(KCOV_INIT_TRACE) was passed a crazily huge
> size.  Perhaps some more realistic checking should be applied there?
> 
> Also, vmalloc() shouldn't be doing this even if asked to allocate a
> crazily huge size.
> 
<snip>
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index bc21d821d506..450c6b10a357 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3783,7 +3783,7 @@ void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
 	if (WARN_ON_ONCE(!size))
 		return NULL;
 
-	if ((size >> PAGE_SHIFT) > totalram_pages()) {
+	if ((size >> PAGE_SHIFT) > totalram_pages() || size > INT32_MAX) {
 		warn_alloc(gfp_mask, NULL,
 			"vmalloc error: size %lu, exceeds total pages",
 			real_size);
<snip>

We can limit it to ~2GB or add a special threshold which will control
the maximum allocation size.

Any thoughts?

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zqj31Kf9_Nb01GYR%40pc638.lan.
