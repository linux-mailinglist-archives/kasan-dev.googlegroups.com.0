Return-Path: <kasan-dev+bncBDXL53XAZIGBBQVQXDEAMGQEXBYO63Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id F1107C40BC7
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 17:03:16 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-43330d77c3asf30101695ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 08:03:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762531395; cv=pass;
        d=google.com; s=arc-20240605;
        b=iHIbMLtQV/teDebbwhVTpdZOHe0bYEQze2zX3oOZdqk/pHy19EO/mWyN6ttID37fgz
         KNe7nkcbf8axlFmOHg7cyhWMGTr9FiNby6EnfgTMeF9O+0h9DgSplwSWqSMppolDe3GP
         PbhWqWbEKfY5MaV0RyzcePffsNsZ2XIDUuM+bPv+84V6JJBKAmcHiQjtvd7/q/7Qyqsw
         AYQXhVtRspG+ate0vR65LAHIBXE+/wp2rerNsympCGdzCr9iBE/aJ06TDhS0ZCcNK5RH
         lpeDEzsfyfo1G6cbY2y47Yo5PjvqVJ5b0S3+FrzX4ALISBhG6vbE0SQsJwmQCHuefSYa
         9C7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SC9JAT6cMqgmdE+Gq9o9huMiIrGWQ1bAEwV5GdTephU=;
        fh=+bxFOQTxKL3fVP9mtLCsjwelQTSMNvJsWiQVa52rtnI=;
        b=bXQkPryXTWNwC66iM72HXhPLf2NelQgCYkvzdmc6MLXpa/w8BNcsa+tAsxTBhUcrpf
         QBCvw3Y0w+TTMv6mZ15agma5O60e6WX/0LQKz7UcOc7CmZkFtVvYk93Wu0QCvG+/TgGF
         1nDs2S3Ueo3Ftp27d2I8SS7W97lZoC0cPx41EbqJW9dsoiZBdK67bvCNtFOKGlsLoRCa
         3e2vVHtzZ4I+dvPn4L+MyjtSrQzoE6FRTO6J+IL7Wit2CXtI+YMPBAf8m3yV6MDTkTh9
         tD0ciFG69XD7BfANekfJ4ckG+L8hf7F4YAtvLHJJ3qw6l4GKlCptwlZKMPhPQGBPakP3
         2npg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mZca7uQQ;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762531395; x=1763136195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SC9JAT6cMqgmdE+Gq9o9huMiIrGWQ1bAEwV5GdTephU=;
        b=dPxydOb+hQwSjKQyl0Lv7Hkaga0pLlG+jKzuJbzbAwZ8So0hE6815+rRtNLRN3wVxh
         rxZ+8UfR7yYRpgr7wApWegUXVtmczalTSi0XKF74a456Qab4k5212b0eSrHH4DagRyk4
         5HDSvD3KIt7VZw/gfpJjHVR+jQvy20aUonBF8QRQcRJ9tOrsEzupHEu+Ez79596Inh+q
         v9/vJZB6qXBfGEn/hyaDHbyAeuXKhwW+MdWJ6QruEqIVIBRAKk1qEc+gbBJRReoXEWOk
         QmOSXuzpYjErjDKeyI64aC9jez5nE8nt2kOseiUE/OFNlMLswmHQ+H2gHmM6XzNLou4u
         e9jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762531395; x=1763136195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SC9JAT6cMqgmdE+Gq9o9huMiIrGWQ1bAEwV5GdTephU=;
        b=SmRVhsp6n1sFMUoN1I6aecknNE37jQxQvlIryz6AujlO/t7QcRrDmNYnNNo762ZwXS
         RiOKgPmqLcq0uBp0mGgskKPhZcz7/4EFqSk9l1KbcKwMcsgpLuBPACVnCDf/qpC6uIos
         tQCNjJn40zCJaw3oVkmENCZ2yrvxaLF2VK7ey3jhQb2Dab5f99Z2svhd8z7tGKFFjIyh
         mq9esw33GYC/f/TILHkR9o18ytvq3zSjv2BAcDYqohpCvgE18fAyKSuNBhA/kLfPKWUR
         YpfCTvLqq2IwwwR2TCycVdRbrHx7W5QAe4b107BYMSLIXRQqQLu7Y3rQD2GKgkyz7phl
         h9XA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBFGhdAsv1FJKIdX8u9nLJSiOnmh0ktlZRmcdoytFxm9Kvy3aw6Jutgx51L/u5Niv8xpFqAw==@lfdr.de
X-Gm-Message-State: AOJu0Yw1dHPNE18zltnHTA2kkSADdLdNSg5g8IzLUQJcDLBf5WzCTe69
	i3Kw5/O9S4m/SAeC83ahY+BZoFez8DqqQDIW+2YxiAmwTtB+6I2FW3ZE
X-Google-Smtp-Source: AGHT+IEpYzlZD0P15RNmPC57vBfj6VBf9FzcR1q4MvqmA8tS8xP3l0bJDoR4dv9j+F67Lws1tY8iEw==
X-Received: by 2002:a05:6e02:198f:b0:433:39bc:2f6e with SMTP id e9e14a558f8ab-4335f47f63fmr53535595ab.26.1762531394719;
        Fri, 07 Nov 2025 08:03:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bd2brBWp9DVneFqGuVYO55OnhYMch9YwuAGbMbcsm2Jg=="
Received: by 2002:a05:6e02:4619:b0:42f:8b38:c20d with SMTP id
 e9e14a558f8ab-4334ee1437els16160965ab.0.-pod-prod-08-us; Fri, 07 Nov 2025
 08:03:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVsyLC3iXVNR+9yNHMuv3P+ube+OqANMk4PKY597znGNl9XtqK8bF7Z5zZ0vEob5Y8XitrLcsx6l2Y=@googlegroups.com
X-Received: by 2002:a05:6e02:3a12:b0:433:575b:9e93 with SMTP id e9e14a558f8ab-4335f48235emr52743135ab.25.1762531391305;
        Fri, 07 Nov 2025 08:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762531391; cv=none;
        d=google.com; s=arc-20240605;
        b=kIco2O3ontJ54TK4I+olq2RES7Yn28QscYtPADAXFNhBxqqI7MiJLEL89MBL8wcDVM
         IIg5J5CWN73WzBiQphlgpFaQ+AIJTcA4dyvbFRS/9F38TVw7OMOxjXRiPEQlX0KiKllZ
         WbdaBgT790bZad22buZaNL6GRSUKA6VSbTtk4tbywoJkPBg6u3gzR7oNxH5ML8z4Fwlc
         z2GNpC6NZkN1vYgU96am+UM9s30jG7zq0nLUErs2SNzE+iWxcDeha057JaDp1AQyXBqd
         MiKTLSsqYzd3/11EwFaWSDm15pRz8vlYmKiwC2Kn56ztLqWWKKlToPCSn0EvBbXIZ3zp
         l3gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=w4A9d23bQNuNhMRhy9flyx2rXxLNd6naylhFbxC/z44=;
        fh=05xDZPCJVkot3PeIiD3W9iaPvWiXB7vxfuBVYOsVC1c=;
        b=LaS/hUYo+WIlSCKkG3ymdH2hkXMdv8q4EbVhp2ipvT7bBDoCgsGgu8CrETLIsspR4/
         flhKhGcec39vYd7uUmFzM6sJFthFQkQzQ+VI46lBo8nP2fxDZ/oFZOdzhza0Vxyz42Ky
         ixyEpxJmS5qN6aQNewDRPjt9CyOAX2eJM6PqceyQGOFWtuseAd1lz9BxQS5BIAG0VzdC
         zyX005ZKpfibPgHhvhDjLoBaqodGwAidCCQWIrKzPKMM54gvnxwRlpRwKb0+2MMwahpC
         DQgb/2jhPKfsbCv0mfW2NtKvu9vx0fEV2Wz89xH3CIR+Zq13LE9J1nCeencHqYUIB8tt
         sWzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mZca7uQQ;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4334f46d294si3047735ab.2.2025.11.07.08.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Nov 2025 08:03:11 -0800 (PST)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5A7Cf4Lk019513;
	Fri, 7 Nov 2025 16:03:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a58mmcg0k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 16:03:10 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5A7Fk1FT017159;
	Fri, 7 Nov 2025 16:03:09 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a58mmcg0h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 16:03:09 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5A7Ergt4027371;
	Fri, 7 Nov 2025 16:03:09 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4a5vwyuqkx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 16:03:09 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5A7G35Bh57541114
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 7 Nov 2025 16:03:05 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1706320040;
	Fri,  7 Nov 2025 16:03:04 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0B2F620043;
	Fri,  7 Nov 2025 16:03:03 +0000 (GMT)
Received: from li-26e6d1cc-3485-11b2-a85c-83dbc1845c5e.ibm.com.com (unknown [9.111.68.113])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri,  7 Nov 2025 16:03:02 +0000 (GMT)
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Heiko Carstens <hca@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Subject: [PATCH v2] s390/fpu: Fix false-positive kmsan report in fpu_vstl function
Date: Fri,  7 Nov 2025 16:59:16 +0100
Message-ID: <20251107155914.1407772-3-aleksei.nikiforov@linux.ibm.com>
X-Mailer: git-send-email 2.43.7
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 9jqrWA-ia39gvYpirWftQH_iDWl3y8Dy
X-Proofpoint-GUID: rPSf5ZDD9EV4xZn6VMao3w7nsr3deqo3
X-Authority-Analysis: v=2.4 cv=SqidKfO0 c=1 sm=1 tr=0 ts=690e183e cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=0aw50RnvYNmxmIOuCV4A:9 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTAxMDAwOSBTYWx0ZWRfX/oSvR0FUaEIT
 3lJoYJ+VTY/Xa3vFCiah4fMxzrrkQOloce+vq2zXj2OQ6eFfLRuCVWxLdrxiQXsXv/7ZZtC94cU
 ZFvQ4gwcOgN7lPJ1jKlwl2bCUHJh8gw56UoadSnSnbypaFIJll7h73svZFjBRfL+Jjxa8FSQGP1
 FVuyjtC4JxIVDo1wet4P/tLdmCFNmciTGwk3ADquAjxswecjnrTsc3XxShiU0tAydCfcHv9hOQK
 Gl+G3PGhzu0WpLns1VUr5WnnUCQgxC4x6biKK7z0skjjJUy14b1DNRh5ZCzolB6GnE9p8l4V2dN
 HVcsX84za0P9jetOhKSvgTbVSIyBEdClEhwcos1Slfl5o90nc3mb7dc8hOhf/Nc4EcWhxQTReCi
 0ChgnGsxKjIXrE8FfeW19yJMt6AwLg==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-07_04,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 suspectscore=0 clxscore=1015 impostorscore=0 adultscore=0 lowpriorityscore=0
 malwarescore=0 spamscore=0 priorityscore=1501 bulkscore=0 phishscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510240000 definitions=main-2511010009
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mZca7uQQ;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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

A false-positive kmsan report is detected when running ping command.

An inline assembly instruction 'vstl' can write varied amount of bytes
depending on value of 'index' argument. If 'index' > 0, 'vstl' writes
at least 2 bytes.

clang generates kmsan write helper call depending on inline assembly
constraints. Constraints are evaluated compile-time, but value of
'index' argument is known only at runtime.

clang currently generates call to __msan_instrument_asm_store with 1 byte
as size. Manually call kmsan function to indicate correct amount of bytes
written and fix false-positive report.

This change fixes following kmsan reports:

[   36.563119] =====================================================
[   36.563594] BUG: KMSAN: uninit-value in virtqueue_add+0x35c6/0x7c70
[   36.563852]  virtqueue_add+0x35c6/0x7c70
[   36.564016]  virtqueue_add_outbuf+0xa0/0xb0
[   36.564266]  start_xmit+0x288c/0x4a20
[   36.564460]  dev_hard_start_xmit+0x302/0x900
[   36.564649]  sch_direct_xmit+0x340/0xea0
[   36.564894]  __dev_queue_xmit+0x2e94/0x59b0
[   36.565058]  neigh_resolve_output+0x936/0xb40
[   36.565278]  __neigh_update+0x2f66/0x3a60
[   36.565499]  neigh_update+0x52/0x60
[   36.565683]  arp_process+0x1588/0x2de0
[   36.565916]  NF_HOOK+0x1da/0x240
[   36.566087]  arp_rcv+0x3e4/0x6e0
[   36.566306]  __netif_receive_skb_list_core+0x1374/0x15a0
[   36.566527]  netif_receive_skb_list_internal+0x1116/0x17d0
[   36.566710]  napi_complete_done+0x376/0x740
[   36.566918]  virtnet_poll+0x1bae/0x2910
[   36.567130]  __napi_poll+0xf4/0x830
[   36.567294]  net_rx_action+0x97c/0x1ed0
[   36.567556]  handle_softirqs+0x306/0xe10
[   36.567731]  irq_exit_rcu+0x14c/0x2e0
[   36.567910]  do_io_irq+0xd4/0x120
[   36.568139]  io_int_handler+0xc2/0xe8
[   36.568299]  arch_cpu_idle+0xb0/0xc0
[   36.568540]  arch_cpu_idle+0x76/0xc0
[   36.568726]  default_idle_call+0x40/0x70
[   36.568953]  do_idle+0x1d6/0x390
[   36.569486]  cpu_startup_entry+0x9a/0xb0
[   36.569745]  rest_init+0x1ea/0x290
[   36.570029]  start_kernel+0x95e/0xb90
[   36.570348]  startup_continue+0x2e/0x40
[   36.570703]
[   36.570798] Uninit was created at:
[   36.571002]  kmem_cache_alloc_node_noprof+0x9e8/0x10e0
[   36.571261]  kmalloc_reserve+0x12a/0x470
[   36.571553]  __alloc_skb+0x310/0x860
[   36.571844]  __ip_append_data+0x483e/0x6a30
[   36.572170]  ip_append_data+0x11c/0x1e0
[   36.572477]  raw_sendmsg+0x1c8c/0x2180
[   36.572818]  inet_sendmsg+0xe6/0x190
[   36.573142]  __sys_sendto+0x55e/0x8e0
[   36.573392]  __s390x_sys_socketcall+0x19ae/0x2ba0
[   36.573571]  __do_syscall+0x12e/0x240
[   36.573823]  system_call+0x6e/0x90
[   36.573976]
[   36.574017] Byte 35 of 98 is uninitialized
[   36.574082] Memory access of size 98 starts at 0000000007aa0012
[   36.574218]
[   36.574325] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Tainted: G    B            N  6.17.0-dirty #16 NONE
[   36.574541] Tainted: [B]=BAD_PAGE, [N]=TEST
[   36.574617] Hardware name: IBM 3931 A01 703 (KVM/Linux)
[   36.574755] =====================================================

[   63.532541] =====================================================
[   63.533639] BUG: KMSAN: uninit-value in virtqueue_add+0x35c6/0x7c70
[   63.533989]  virtqueue_add+0x35c6/0x7c70
[   63.534940]  virtqueue_add_outbuf+0xa0/0xb0
[   63.535861]  start_xmit+0x288c/0x4a20
[   63.536708]  dev_hard_start_xmit+0x302/0x900
[   63.537020]  sch_direct_xmit+0x340/0xea0
[   63.537997]  __dev_queue_xmit+0x2e94/0x59b0
[   63.538819]  neigh_resolve_output+0x936/0xb40
[   63.539793]  ip_finish_output2+0x1ee2/0x2200
[   63.540784]  __ip_finish_output+0x272/0x7a0
[   63.541765]  ip_finish_output+0x4e/0x5e0
[   63.542791]  ip_output+0x166/0x410
[   63.543771]  ip_push_pending_frames+0x1a2/0x470
[   63.544753]  raw_sendmsg+0x1f06/0x2180
[   63.545033]  inet_sendmsg+0xe6/0x190
[   63.546006]  __sys_sendto+0x55e/0x8e0
[   63.546859]  __s390x_sys_socketcall+0x19ae/0x2ba0
[   63.547730]  __do_syscall+0x12e/0x240
[   63.548019]  system_call+0x6e/0x90
[   63.548989]
[   63.549779] Uninit was created at:
[   63.550691]  kmem_cache_alloc_node_noprof+0x9e8/0x10e0
[   63.550975]  kmalloc_reserve+0x12a/0x470
[   63.551969]  __alloc_skb+0x310/0x860
[   63.552949]  __ip_append_data+0x483e/0x6a30
[   63.553902]  ip_append_data+0x11c/0x1e0
[   63.554912]  raw_sendmsg+0x1c8c/0x2180
[   63.556719]  inet_sendmsg+0xe6/0x190
[   63.557534]  __sys_sendto+0x55e/0x8e0
[   63.557875]  __s390x_sys_socketcall+0x19ae/0x2ba0
[   63.558869]  __do_syscall+0x12e/0x240
[   63.559832]  system_call+0x6e/0x90
[   63.560780]
[   63.560972] Byte 35 of 98 is uninitialized
[   63.561741] Memory access of size 98 starts at 0000000005704312
[   63.561950]
[   63.562824] CPU: 3 UID: 0 PID: 192 Comm: ping Tainted: G    B            N  6.17.0-dirty #16 NONE
[   63.563868] Tainted: [B]=BAD_PAGE, [N]=TEST
[   63.564751] Hardware name: IBM 3931 A01 703 (KVM/Linux)
[   63.564986] =====================================================

Fixes: dcd3e1de9d17 ("s390/checksum: provide csum_partial_copy_nocheck()")
Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
---
 arch/s390/include/asm/fpu-insn.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/s390/include/asm/fpu-insn.h b/arch/s390/include/asm/fpu-insn.h
index 135bb89c0a89..8f2dd6e879ff 100644
--- a/arch/s390/include/asm/fpu-insn.h
+++ b/arch/s390/include/asm/fpu-insn.h
@@ -12,6 +12,7 @@
 #ifndef __ASSEMBLER__
 
 #include <linux/instrumented.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 
 asm(".include \"asm/fpu-insn-asm.h\"\n");
@@ -393,6 +394,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 index, const void *vxr)
 		     : [vxr] "=Q" (*(u8 *)vxr)
 		     : [index] "d" (index), [v1] "I" (v1)
 		     : "memory");
+	kmsan_unpoison_memory(vxr, size);
 }
 
 #else /* CONFIG_CC_HAS_ASM_AOR_FORMAT_FLAGS */
@@ -409,6 +411,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 index, const void *vxr)
 		: [vxr] "=R" (*(u8 *)vxr)
 		: [index] "d" (index), [v1] "I" (v1)
 		: "memory", "1");
+	kmsan_unpoison_memory(vxr, size);
 }
 
 #endif /* CONFIG_CC_HAS_ASM_AOR_FORMAT_FLAGS */
-- 
2.43.7

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251107155914.1407772-3-aleksei.nikiforov%40linux.ibm.com.
