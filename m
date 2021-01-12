Return-Path: <kasan-dev+bncBCH2XPOBSAERBMWY6X7QKGQEV6LIDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id C08702F2B44
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:30:27 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id w9sf1203269pjh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 01:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610443826; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9E+zwXaIAFem37dpiprWVTfDcqt6Z6Uh0GTeB3135LAObP7LJLk5FWioiPgt2FW0W
         Hk9PKzFm6xpcd9QtQgJPVIY1geo/PhEr0QjEDduY0s1M7VbsqjFNdydncO0CpiMycUjS
         47Kwml54O9HNTIK9bE0K9X+pcZRNzvppbyKXCXaLiW9C6uDBeFc8ivncvX0QelBgMVIy
         6FIt+6XKU1bTo3JV/laBgUOanTt5/+OjjfwPqzeGU/E8luUVryK9iW9EQjjrUlMqehH8
         okgO4NDSTD/EGG15mmkzpcWYpad11nrirHLbBHP0c/mJ8UJUPPGLhmXprk8RtRuOORu8
         mGRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Frn1zxKY2wJ+pi+/vNYR64gBbfi8bdF87vfbO4coFoI=;
        b=IQF53aTNxbDnUcRsON9GcSvFhz0GleBRuwqWQXRS35xj4TAqGujUooNT+sMINPlDme
         8ybpx+gYU9eUW4OcYI7+ACwFLuOZrt7FiNKuDlFCDJcaYOzIWGyL9ltjO1fqOyT/d+L1
         jXDWkFeBw8nO5dTUwd4Ku4bd5RD4B69rUFDtm/ONp1fGZnbVYmK8XEeGlAJOPYZT/RfM
         MBpTWi66T6XCKH3kH7syYacU9+Vv2i2ZOMva1I920FFZPMtoGF40gycC5aAjwyRUKBzr
         7s5yHbilJvF4mlHuxwM7EtEyfNDCMAD6Ct9Cm+QgpagGs/fYv+6ZTl8CDlC+kqT1qq3G
         wOpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=fhlt5bvX;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Frn1zxKY2wJ+pi+/vNYR64gBbfi8bdF87vfbO4coFoI=;
        b=K1EY54LWbvbCKclPeSyfVn3bFyAn7T0r5Gh4NKZU3yZSAvQ4+ki9x2dyj/Pv+dcBA4
         twZjsjA16wTickR+zqPi6OsGwg78kT3KjHGfAIw8BWKmO1UNZjhvgCRA3iAF7YXodlyb
         k/6q6RplVwv+kGxqTkrWoSngZzuRqyr7MVPprttzu0iVhDHpbOrz7EsVNLqPhxWzpCUG
         wx7pU5yDqKDv0eZGswZolQBBk2Wq98yFcQW8pzkuLEPFzlrEYyJEAVZ/VHgmCq410Tj6
         SWKbp9iQEyXfcxfpmA3V8ieKlFp2q3mXmtOnsuRARAbf5LnVSR5iuDxehm4esNQ9CQQT
         ilSQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Frn1zxKY2wJ+pi+/vNYR64gBbfi8bdF87vfbO4coFoI=;
        b=ZeAM4HbqS+RcDF5tmmNTwgSs4IHjuLoZoErgCwKxePsva2EPAP3usgePSDmgX1HT6i
         apKv95rIxX7sQ1MLxv808CAcO68S619Ykh0H1mduSoXX0H82zaunpL5CjYnh6H6iV4VD
         2gBPExF9ElCA8un2OKSXm0TZ5pw68rVJ8Hh/hZ471NFfgr2qYJPtkruZs6sG+VsRDotb
         BV+sDyE20GD5iAbzUTENwaGgUNW8K+ioph+45TdcYtc+JCCHOxqi8bFBVCo1NOpm4cpY
         A70OKcYLG2r1c6rBA8kg6hsedVo2SVpIryRXDuyjZKJan9Hh0nLUs9cBp6vVrHMTUYiv
         R3bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Frn1zxKY2wJ+pi+/vNYR64gBbfi8bdF87vfbO4coFoI=;
        b=oMosxrNpBrzTYfJkyoOi7tM7Kznu/MnHLZav/MbBL17kmfhtZLrLDgCgGU8SRbDdbN
         sKCZf2+SQ72W0e05W9CJFg2yaeP0I2NqyF/Azh+Iwh+elZC+ODpor0niCyn2/SWRDF6Q
         7ylDEC70ryMpy0X9JZCbjtZsl2pGVoZXA6ojHDEnlAK1HP/ZhomZDIpk8qQfVlmAqyWP
         PUHBlGrFp4jvQ7ne0E8tYmFhFYQ3VDD+ov684aF+rw1LGMHlCRLEzqXiIODzr8DPEcdT
         ga85bv+sIon0MKlsSvIGR/LfO8/LUqyXT5y+LjEqt95LJNPBPBraGXLvrlmfLgPpiywf
         S+xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Msl+OA+KZs6Q91J9mU9DW30dfkt4p5te8MCv7dWVpMAnKBDTB
	ZO89KYerxU4WHLLEeIPgqQY=
X-Google-Smtp-Source: ABdhPJz0Paoh5w3yC+7VfTeYAXZ96INmnLTW7JN9o857qB3gpHlsy4nYcUMkA4cVAuecwpQHxO4czQ==
X-Received: by 2002:a62:f948:0:b029:1ad:c27d:2b9e with SMTP id g8-20020a62f9480000b02901adc27d2b9emr3948882pfm.33.1610443826260;
        Tue, 12 Jan 2021 01:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd46:: with SMTP id a6ls1020418pgj.2.gmail; Tue, 12 Jan
 2021 01:30:25 -0800 (PST)
X-Received: by 2002:a05:6a00:a88:b029:19e:4ba8:bbe4 with SMTP id b8-20020a056a000a88b029019e4ba8bbe4mr3830352pfl.41.1610443825712;
        Tue, 12 Jan 2021 01:30:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610443825; cv=none;
        d=google.com; s=arc-20160816;
        b=vUfv4lpYC+ylcFrwzHwiruxE2yS/BdqIMfJCahNQEde/MXLnsocCob1sN0OHDAcsxj
         dMwykzgBMkyssVKKpD9EdkaeovLbGqUKE1OmNQbInet5LUQOO+eX8rQl/NH5khfs29w0
         vfi7RmKUmNMjqDxJByJDlS/0tsalKOBeQoZf+iGr7rYBwq7zeW3hGUdS7JLoZnAkxlk6
         p3AABhyJ/AUhsbDOee/NIW7PkZ8fOQDyOvZ8iS7gfFC5wp/2TraJ8RKJ0lbFRqX3LGLG
         PLjyqdLMbSxaD9IcGuMrHJtOnIPLHUJMCsoUacFYRSpW30w2i2sw5jX4xbZhuU7QsPiz
         l9lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=V5WnApEwuSQnWao8Us1cXdPUKfn4JCQraxNiwfzFRJA=;
        b=mi0r/TeC5RhQBqgLpnPjqJNuiudw7+JXu8OHBhOKS7VthOWF5P7JlSsfF8i4rWmoOs
         riBHEvFDr3D25dGQ3H9LZwMPprPKZjY+Dex+GVUwC5c7CC7dxRpMZyzaUjt48UAF3S4W
         Lo23KGYPPtMy4RA71CeG3gC6K/NPANqPw64MOpv5a3CjY5OGWBBdPK5vNK+gtU4RzaQj
         XC5AC7aAsR4Jk3v3tOd75EwxytXHpWtdVFocdx/OWK3+RctWMH+2pnvzSh/jyYzzaQe9
         dBQepuj0AvUP2mAhKDKLiULrLOtHNUtGJYB4fOIJ8G+PK7kkeTzIfGmtmuGpZ36VwFvG
         6zFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=fhlt5bvX;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id d2si148495pfr.4.2021.01.12.01.30.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 01:30:25 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id x6so1105106ybr.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 01:30:25 -0800 (PST)
X-Received: by 2002:a25:141:: with SMTP id 62mr5488146ybb.426.1610443824722;
 Tue, 12 Jan 2021 01:30:24 -0800 (PST)
MIME-Version: 1.0
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Tue, 12 Jan 2021 17:29:58 +0800
Message-ID: <CAD-N9QUZzBtGAk7Tghf+ZXxnnjPuSvHLHTs3imM5N9ZmVFSC7g@mail.gmail.com>
Subject: When KASAN reports GPF, when KASAN reports NULL pointer dereference?
To: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=fhlt5bvX;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi all,

from my basic understanding, KASAN can catch invalid memory access,
such as NULL pointer dereference. However, recently I encountered one
case - BUG: unable to handle kernel NULL pointer dereference in
x25_connect(https://syzkaller.appspot.com/bug?id=e4a61ec2a7dc1ec61617142a0f7a7d0427f8c442),
the kernel reports "BUG: unable to handle kernel NULL pointer
dereference" with KASAN enabled. I don't understand why this occurs.

-----------------------------------------------------------------------------------------------------
BUG: kernel NULL pointer dereference, address: 00000000000000c8
#PF: supervisor write access in kernel mode
#PF: error_code(0x0002) - not-present page
PGD 97b39067 P4D 97b39067 PUD a2fba067 PMD 0
Oops: 0002 [#1] PREEMPT SMP KASAN
-----------------------------------------------------------------------------------------------------

If any above description is incorrect, please let me know.

--
My best regards to you.

     No System Is Safe!
     Dongliang Mu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAD-N9QUZzBtGAk7Tghf%2BZXxnnjPuSvHLHTs3imM5N9ZmVFSC7g%40mail.gmail.com.
